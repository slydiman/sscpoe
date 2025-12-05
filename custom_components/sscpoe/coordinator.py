from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import (
    HomeAssistantError,
    ConfigEntryAuthFailed,
)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.const import (
    CONF_ID,
    CONF_IP_ADDRESS,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_TOKEN,
)

import hashlib
import asyncio
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_CLOUD_KEY,
    SSCPOE_LOCAL_DEF_PASSWORD,
    SSCPOE_cloud_request,
    SSCPOE_local_request,
    SSCPOE_local_login,
    SSCPOE_web_request,
    SSCPOE_web_login2,
)


class SSCPOE_Coordinator(DataUpdateCoordinator):

    LOCAL_PID = "local"
    WEB_PID = "web"

    def is_cloud(pid):
        return pid != SSCPOE_Coordinator.LOCAL_PID and pid != SSCPOE_Coordinator.WEB_PID

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry):
        self._sn = config_entry.data.get(CONF_ID, None)
        self._ip = config_entry.data.get(CONF_IP_ADDRESS, None)
        self._email = config_entry.data.get(CONF_EMAIL, None)
        self._password = config_entry.data[CONF_PASSWORD]
        self._key = SSCPOE_CLOUD_KEY
        self._uid = config_entry.data.get(CONF_TOKEN, None)
        self._uid_write = False
        self.prj = None
        self.devices = None

        super().__init__(
            hass,
            LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
        )

    def reverse_order(self, sn: str) -> bool:
        # Correct port order: PS308G, GPS316.
        # Reverse port order: GPS204, GPS208, GPS1xx, GS105.
        return sn.startswith("GPS1") or sn.startswith("GPS2") or sn.startswith("GS1")

    def write_token(self) -> None:
        if self._uid_write:
            new_data = {**self.config_entry.data}
            if self._uid:
                new_data[CONF_TOKEN] = self._uid
            elif CONF_TOKEN in new_data:
                new_data.pop(CONF_TOKEN)
            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data=new_data,
            )
            self._uid_write = False

    async def _async_update_data(self) -> None:
        try:
            async with asyncio.timeout(10):
                await self.hass.async_add_executor_job(self._update_data)
        except ApiAuthError as err:
            self._uid = None
            self.write_token()
            # Raising ConfigEntryAuthFailed will cancel future updates
            # and start a config flow with SOURCE_REAUTH (async_step_reauth)
            raise ConfigEntryAuthFailed from err
        except ApiError as err:
            self._uid = None
            self.write_token()
            raise UpdateFailed(f"Error communicating with API: {err}")
        self.write_token()

    def _update_data(self) -> None:
        if self._sn:
            self._update_data_local()
        elif self._ip:
            self._update_data_web()
        elif self._email:
            self._update_data_cloud()

    def _update_data_local(self) -> None:
        j, err = SSCPOE_local_request({"callcmd": "detail", "sn": self._sn})
        if j is None:
            # Second try
            j, err = SSCPOE_local_request({"callcmd": "detail", "sn": self._sn})
            if j is None:
                raise ApiError(f"SSCPOE_local_request(detail, {self._sn}): timeout")
        if isinstance(j, str):
            LOGGER.debug(
                f"SSCPOE_Coordinator._fetch_data: login/activate with the default passowrd."
            )
            if (
                SSCPOE_local_login(self._sn, SSCPOE_LOCAL_DEF_PASSWORD) is None
                or SSCPOE_local_login(self._sn, SSCPOE_LOCAL_DEF_PASSWORD, "activate")
                is None
            ):
                # Second try after login/activate.
                j, err = SSCPOE_local_request({"callcmd": "detail", "sn": self._sn})
                if j is None:
                    raise ApiError(f"SSCPOE_local_request(detail, {self._sn}): timeout")
            if isinstance(j, str):
                raise ApiAuthError(j)
        if err != 0:
            raise ApiError(f"SSCPOE_local_request(detail, {self._sn}) errcode={err}")
        if self.prj is None:
            self.prj = {}
            self.prj[self.LOCAL_PID] = {"pid": self.LOCAL_PID, "name": "Local"}
        if self.devices is None:
            self.devices = {}
            self.devices[self._sn] = {"pid": self.LOCAL_PID, "sn": self._sn}
        device = self.devices[self._sn]
        detail = j["calldata"]
        detail["name"] = self._sn
        device["detail"] = detail
        if not ("device_info" in device):
            model = self._sn[0:6]
            if (
                model[0].isalpha()
                and model[1].isalpha()
                and model[2].isdigit()
                and model[3].isdigit()
                and model[4].isdigit()
                and model[5].isdigit()
            ):
                # Model may be AAADDD###, AADDDA### or AADDD### (GS105)
                model = model[:-1]
            device["device_info"] = DeviceInfo(
                identifiers={(DOMAIN, self._sn)},
                manufacturer="STEAMEMO",
                model=model,
                name=detail["name"],
                sw_version=detail["V"],
                connections={
                    (CONNECTION_NETWORK_MAC, detail["mac"])
                },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
            )

    def _update_data_web(self) -> None:
        if self._uid is None:
            self._uid, err = SSCPOE_web_login2(self._ip, self._password, self._uid)
            if self._uid is None or err != 0:
                raise ApiAuthError(f"ip={self._ip}, errcode={err}")
            self._uid_write = True
        j, err = SSCPOE_web_request(self._ip, self._uid, 101)
        if j is None or err != 0:
            self._uid = None
            self._uid_write = True
            raise ApiError(f"SSCPOE_web_request({self._ip}, 101) errcode={err}")
        detail = j["calldata"]
        _sn = detail["sn"]
        if self.prj is None:
            self.prj = {}
            self.prj[self.WEB_PID] = {"pid": self.WEB_PID, "name": "WEB"}
        if self.devices is None:
            self.devices = {}
            self.devices[_sn] = {"pid": self.WEB_PID, "sn": _sn}
        device = self.devices[_sn]
        detail["name"] = _sn
        device["detail"] = detail
        if not ("device_info" in device):
            model = _sn[0:6]
            if (
                model[0].isalpha()
                and model[1].isalpha()
                and model[2].isdigit()
                and model[3].isdigit()
                and model[4].isdigit()
                and model[5].isdigit()
            ):
                # Model may be AAADDD###, AADDDA### or AADDD### (GS105)
                model = model[:-1]
            device["device_info"] = DeviceInfo(
                identifiers={(DOMAIN, _sn)},
                manufacturer="STEAMEMO",
                model=model,
                name=detail["name"],
                sw_version=detail["V"],
                connections={
                    (CONNECTION_NETWORK_MAC, detail["mac"])
                },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
            )

    def _update_data_cloud(self) -> None:
        if self._uid is None:
            eml = {
                "email": self._email,
                "pd": hashlib.md5(self._password.encode("utf-8")).hexdigest(),
            }
            j = SSCPOE_cloud_request("eml", eml, SSCPOE_CLOUD_KEY, None)
            if j is None:
                raise ApiError("SSCPOE_cloud_request(eml): unknown")
            if j["errcode"] != 0:
                raise ApiAuthError(f'errcode={j["errcode"]}')
            self._uid = j["uid"]
            self._key = j["key"]

        if self.devices is None:
            if self.prj is None:
                j = SSCPOE_cloud_request("prjmng", None, self._key, self._uid)
                if j is None:
                    raise ApiError("SSCPOE_cloud_request(prjmng): unknown")
                self.prj = {}
                for p in j["admin"] + j["join"]:
                    pid = p["pid"]
                    self.prj[pid] = p
                    j = SSCPOE_cloud_request(
                        "swmng", {"pid": pid}, self._key, self._uid
                    )
                    if j is None:
                        raise ApiError("SSCPOE_cloud_request(swmng): unknown")
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
                raise ApiError("SSCPOE_cloud_request(swdet): unknown")
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

    async def _async_switch_poe(
        self, pid: str, sn: str, index: int, poec: bool
    ) -> None:
        try:
            async with asyncio.timeout(10 if SSCPOE_Coordinator.is_cloud(pid) else 2):
                return await self.hass.async_add_executor_job(
                    self._switch_poe, pid, sn, index, poec
                )
        except ApiError as ex:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {ex}")

    async def _async_switch_extend(
        self, pid: str, sn: str, index: int, extend: bool
    ) -> None:
        try:
            async with asyncio.timeout(10 if SSCPOE_Coordinator.is_cloud(pid) else 2):
                return await self.hass.async_add_executor_job(
                    self._switch_extend, pid, sn, index, extend
                )
        except ApiError as ex:
            self._uid = None
            raise UpdateFailed(f"Error communicating with API: {ex}")

    def _switch_poe(self, pid: str, sn: str, index: int, poec: bool) -> None:
        opcode = (0x202 if poec else 2) | (index << 4)
        err = self._switch(pid, sn, opcode)
        if err != 0:
            self._uid = None
            raise UpdateFailed(f"_switch_poe: errcode={err}")

    def _switch_extend(self, pid: str, sn: str, index: int, extend: bool) -> None:
        # 0x200: phyc = 1: 10MBit half duplex
        # 0x400: phyc = 2: 10MBit full duplex
        # 0x800: phyc = 4: 100MBit full duplex
        # 0xA00: phyc = 5: 1GBit full duplex
        # 0xC00: err=1001 # GS105
        opcode = (0x400 if extend else 0xA00) | (index << 4)
        for i in range(2):
            err = self._switch(pid, sn, opcode)
            if err == 0:
                break
            if i == 0 and err == 1001:
                opcode = (0x200 if extend else 0x800) | (index << 4)
                continue
            self._uid = None
            raise UpdateFailed(f"_switch_extend: errcode={err}")

    def _switch(self, pid: str, sn: str, opcode: int) -> int:
        if SSCPOE_Coordinator.is_cloud(pid):
            return self._switch_cloud(pid, sn, opcode)
        if self._ip:
            return self._switch_web(opcode)
        else:
            return self._switch_local(opcode)

    def _switch_local(self, opcode: int) -> int:
        j, err = SSCPOE_local_request(
            {
                "callcmd": "config",
                "calldata": {"opcode": opcode},
                "sn": self._sn,
            }
        )
        if j is None:
            raise ApiError("SSCPOE_local_request(config): timeout")
        return err

    def _switch_web(self, opcode: int) -> int:
        if self._uid is None:
            return 10001
        j, err = SSCPOE_web_request(self._ip, self._uid, 103, {"opcode": opcode})
        if j is None or err != 0:
            raise ApiError(
                f"SSCPOE_web_request({self._ip}, 103, opcode: {opcode}) errcode={err}"
            )
        return err

    def _switch_cloud(self, pid: str, sn: str, opcode: int) -> int:
        if self._uid is None:
            return 10001
        swconf = {
            "pid": pid,
            "sn": sn,
            "opcode": opcode,
        }
        j = SSCPOE_cloud_request("swconf", swconf, self._key, self._uid)
        if j is None:
            raise ApiError("SSCPOE_cloud_request(swconf): unknown")
        err = int(j["data"]["errcode"])
        return err


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""
