from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import asyncio
import hashlib
import async_timeout
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import SSCPOE_KEY, SSCPOE_request

PLATFORMS: list[str] = [Platform.SENSOR, Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = SSCPOE_Coordinator(
        hass, entry.data[CONF_EMAIL], entry.data[CONF_PASSWORD]
    )
    await coordinator.async_config_entry_first_refresh()
    entry.async_on_unload(entry.add_update_listener(update_listener))
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update listener."""
    await hass.config_entries.async_reload(entry.entry_id)


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""


class SSCPOE_Coordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, email: str, password: str):
        self._email = email
        self._password = password
        self._key = SSCPOE_KEY
        self._uid = None
        self.prj = None
        self.devices = None

        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
        )

    async def _async_update_data(self) -> None:
        try:
            async with async_timeout.timeout(10):
                return await self.hass.async_add_executor_job(self._fetch_data)
        except ApiAuthError as err:
            self._uid = None
            # Raising ConfigEntryAuthFailed will cancel future updates
            # and start a config flow with SOURCE_REAUTH (async_step_reauth)
            raise ConfigEntryAuthFailed from err
        except ApiError as err:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {err}")

    def _fetch_data(self) -> None:
        if self._uid is None:
            eml = {
                "email": self._email,
                "pd": hashlib.md5(self._password.encode("utf-8")).hexdigest(),
            }
            j = SSCPOE_request("eml", eml, SSCPOE_KEY, None)
            if j is None:
                raise ApiError
            if j["errcode"] != 0:
                raise ApiAuthError
            self._uid = j["uid"]
            self._key = j["key"]

        if self.devices is None:
            if self.prj is None:
                j = SSCPOE_request("prjmng", None, self._key, self._uid)
                if j is None:
                    raise ApiError
                self.prj = {}
                for p in j["admin"]:
                    pid = p["pid"]
                    self.prj[pid] = p
                    j = SSCPOE_request("swmng", {"pid": pid}, self._key, self._uid)
                    if j is None:
                        raise ApiError
                    p["online"] = j["online"]
            self.devices = {}
            for i, pid in enumerate(self.prj):
                p = self.prj[pid]
                for s in p["online"]:
                    sn = s["sn"]
                    self.devices[sn] = {"pid": pid, "sn": sn}

        for i, sn in enumerate(self.devices):
            device = self.devices[sn]
            j = SSCPOE_request(
                "swdet",
                {"pid": device["pid"], "sn": sn, "isJoin": "1"},
                self._key,
                self._uid,
            )
            if j is None:
                raise ApiError
            detail = j["detail"]
            device["detail"] = detail
            if not ("device_info" in device):
                device["device_info"] = DeviceInfo(
                    identifiers={(DOMAIN, sn)},
                    manufacturer="STEAMEMO",
                    model=sn[0:6],
                    name=detail["name"],
                    sw_version=detail["V"],
                    connections={
                        (CONNECTION_NETWORK_MAC, detail["mac"])
                    },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
                )

    async def _async_switch_poe(self, pid: str, sn: str, port: int, poec: bool) -> None:
        try:
            async with async_timeout.timeout(10):
                return await self.hass.async_add_executor_job(
                    self._switch_poe, pid, sn, port, poec
                )
        except ApiError as err:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {err}")

    def _switch_poe(self, pid: str, sn: str, port: int, poec: bool) -> None:
        if self._uid:
            swconf = {
                "pid": pid,
                "sn": sn,
                "opcode": (0x202 if poec else 2) | (port << 4),
            }
            j = SSCPOE_request("swconf", swconf, self._key, self._uid)
            if j is None:
                raise ApiError
