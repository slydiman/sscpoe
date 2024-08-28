from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
import hashlib
import async_timeout
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import SSCPOE_CLOUD_KEY, SSCPOE_cloud_request, SSCPOE_local_request


class SSCPOE_Coordinator(DataUpdateCoordinator):

    local_pid = "local"

    def __init__(self, hass: HomeAssistant, sn: str, email: str, password: str):
        self._sn = sn
        self._email = email
        self._password = password
        self._key = SSCPOE_CLOUD_KEY
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
        if self._sn:
            j, err = SSCPOE_local_request({"callcmd": "detail", "sn": self._sn})
            if j is None:
                return
            if err != 0:
                raise ApiError(f"local errcode={err}")
            if self.prj is None:
                self.prj = {}
                self.prj[self.local_pid] = {"pid": self.local_pid, "name": "Local"}
            if self.devices is None:
                self.devices = {}
                self.devices[self._sn] = {"pid": self.local_pid, "sn": self._sn}
            device = self.devices[self._sn]
            detail = j["calldata"]
            detail["name"] = self._sn
            device["detail"] = detail
            if not ("device_info" in device):
                device["device_info"] = DeviceInfo(
                    identifiers={(DOMAIN, self._sn)},
                    manufacturer="STEAMEMO",
                    model=self._sn[0:6],
                    name=detail["name"],
                    sw_version=detail["V"],
                    connections={
                        (CONNECTION_NETWORK_MAC, detail["mac"])
                    },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
                )
        elif self._email:
            if self._uid is None:
                eml = {
                    "email": self._email,
                    "pd": hashlib.md5(self._password.encode("utf-8")).hexdigest(),
                }
                j = SSCPOE_cloud_request("eml", eml, SSCPOE_CLOUD_KEY, None)
                if j is None:
                    raise ApiError
                if j["errcode"] != 0:
                    raise ApiAuthError(f'errcode={j["errcode"]}')
                self._uid = j["uid"]
                self._key = j["key"]

            if self.devices is None:
                if self.prj is None:
                    j = SSCPOE_cloud_request("prjmng", None, self._key, self._uid)
                    if j is None:
                        raise ApiError
                    self.prj = {}
                    for p in j["admin"] + j["join"]:
                        pid = p["pid"]
                        self.prj[pid] = p
                        j = SSCPOE_cloud_request(
                            "swmng", {"pid": pid}, self._key, self._uid
                        )
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
                j = SSCPOE_cloud_request(
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
            if self._sn:
                async with async_timeout.timeout(2):
                    return await self.hass.async_add_executor_job(
                        self._switch_poe_local, self._sn, port, poec
                    )
            elif self._email:
                async with async_timeout.timeout(10):
                    return await self.hass.async_add_executor_job(
                        self._switch_poe_cloud, pid, sn, port, poec
                    )
        except ApiError as err:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {err}")

    def _switch_poe_local(self, sn: str, port: int, poec: bool) -> None:
        j, err = SSCPOE_local_request(
            {
                "callcmd": "config",
                "calldata": {"opcode": (0x202 if poec else 2) | (port << 4)},
                "sn": self._sn,
            }
        )
        if j is None:
            raise ApiError
        if err != 0:
            raise ApiError(f"local errcode={err}")

    def _switch_poe_cloud(self, pid: str, sn: str, port: int, poec: bool) -> None:
        if self._uid:
            swconf = {
                "pid": pid,
                "sn": sn,
                "opcode": (0x202 if poec else 2) | (port << 4),
            }
            j = SSCPOE_cloud_request("swconf", swconf, self._key, self._uid)
            if j is None:
                raise ApiError


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""
