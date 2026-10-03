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
    CONF_IF,
    CONF_TTL,
)

import asyncio
from datetime import timedelta
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_CLOUD_KEY,
    SSCPOE_LOCAL_DEF_PASSWORD,
    SSCPOE_LOCAL_DEF_BIND_INTERFACE,
    SSCPOE_LOCAL_DEF_TTL,
    SSCPOE_local_request,
    SSCPOE_local_login,
    SSCPOE_web_cmd,
    SSCPOE_session,
    SSCPOE_model_from_sn,
)


class SSCPOE_Coordinator(DataUpdateCoordinator):

    LOCAL_PID = "local"
    WEB_PID = "web"

    def is_cloud(pid):
        return pid != SSCPOE_Coordinator.LOCAL_PID and pid != SSCPOE_Coordinator.WEB_PID

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry):
        self._session = SSCPOE_session()
        self._sn = config_entry.data.get(CONF_ID, None)
        self._ip = config_entry.data.get(CONF_IP_ADDRESS, None)
        self._email = config_entry.data.get(CONF_EMAIL, None)
        self._password = config_entry.data[CONF_PASSWORD]
        self._key = SSCPOE_CLOUD_KEY
        self._uid = config_entry.data.get(CONF_TOKEN, None)
        self._uid_write = False
        self._ifname = config_entry.data.get(CONF_IF, SSCPOE_LOCAL_DEF_BIND_INTERFACE)
        self._ttl = config_entry.data.get(CONF_TTL, SSCPOE_LOCAL_DEF_TTL)
        self.prj = None
        self.devices = None

        super().__init__(
            hass,
            LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
            config_entry=config_entry,
        )

    def reverse_order(sn: str) -> bool:
        # Correct port order: PS208G, PS308G, GPS316.
        # Reverse port order: GPS204, GPS208, GFS226V1, GPS424V3, GPS1xx, GS105.
        return (
            sn.startswith("GS1")
            or sn.startswith("GPS1")
            or sn.startswith("GPS2")
            or sn.startswith("GFS2")
            or sn.startswith("GPS4")
        )

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
        except Exception as ex:
            if isinstance(ex, ApiAuthError):
                self._uid = None
                self._uid_write = True
                self.write_token()
                # Raising ConfigEntryAuthFailed will cancel future updates
                # and start a config flow with SOURCE_REAUTH (async_step_reauth)
                raise ConfigEntryAuthFailed from ex
            else:  # ApiError or TimeoutError
                if not self._email:  # Don't relogin the cloud account
                    self._uid = None
                    self._uid_write = True
                self.write_token()
                raise UpdateFailed(f"Error communicating with API: {str(ex)}")
        self.write_token()

    def _update_data(self) -> None:
        if self._sn:
            self._update_data_local()
        elif self._ip:
            self._update_data_web()
        elif self._email:
            self._update_data_cloud()

    def _update_data_local(self) -> None:
        for i in range(2):
            j, err = SSCPOE_local_request(
                {"callcmd": "detail", "sn": self._sn}, self._ifname, self._ttl
            )
            if j is not None:
                break
            if i > 0:
                raise ApiError(f"SSCPOE_local_request(detail, {self._sn}): {err}")
            err1 = err
            err = SSCPOE_local_login(
                self._sn,
                self._password,
                "login",
                self._ifname,
                self._ttl,
            )
            if err:
                err = SSCPOE_local_login(
                    self._sn,
                    self._password,
                    "activate",
                    self._ifname,
                    self._ttl,
                )
            if err:
                if err.startswith("auth"):
                    raise ApiAuthError(err1)
                else:
                    raise ApiError(err1)

        if self.prj is None:
            self.prj = {}
            self.prj[self.LOCAL_PID] = {"pid": self.LOCAL_PID, "name": "Local"}
        if self.devices is None:
            self.devices = {}
            self.devices[self._sn] = {"pid": self.LOCAL_PID, "sn": self._sn}
        device = self.devices[self._sn]
        detail = j["calldata"]
        detail["name"] = self._sn
        detail["online"] = True
        device["detail"] = detail
        if not ("device_info" in device):
            device["device_info"] = DeviceInfo(
                identifiers={(DOMAIN, self._sn)},
                manufacturer="STEAMEMO",
                model=device.get("model", SSCPOE_model_from_sn(self._sn)),
                name=detail["name"],
                sw_version=detail["V"],
                connections={
                    (CONNECTION_NETWORK_MAC, detail["mac"])
                },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
            )

    def _update_data_web(self) -> None:
        for i in range(2):
            if self._uid is not None:
                j, err = self._session.web_request(
                    self._ip, self._uid, SSCPOE_web_cmd.get_detail
                )
                if j is not None:
                    break
                self._uid = None
                self._uid_write = True
                if i > 0:
                    raise ApiError(
                        f"SSCPOE_web_request({self._ip}, {SSCPOE_web_cmd.get_detail}) err={err}"
                    )
            self._uid, err = self._session.web_login(
                self._ip, self._password, self._uid
            )
            if self._uid is None:
                if err == "wrong_password":
                    raise ApiAuthError(f"web_login(ip={self._ip}), err={err}")
                else:
                    raise ApiError(f"web_login(ip={self._ip}), err={err}")
            self._uid_write = True

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
        detail["online"] = True
        device["detail"] = detail
        if not ("device_info" in device):
            device["device_info"] = DeviceInfo(
                identifiers={(DOMAIN, _sn)},
                manufacturer="STEAMEMO",
                model=device.get("model", SSCPOE_model_from_sn(_sn)),
                name=detail["name"],
                sw_version=detail["V"],
                connections={
                    (CONNECTION_NETWORK_MAC, detail["mac"])
                },  # ,(CONF_IP_ADDRESS, self._device.detail['ip'])
            )

    def _update_data_cloud(self) -> None:
        if self._uid is None:
            j, err = self._session.cloud_login(self._email, self._password)
            if j is None:
                if err == "wrong_password":
                    raise ApiAuthError(f"cloud_login(email={self._email}): {err}")
                else:
                    raise ApiError(f"cloud_login(email={self._email}): {err}")
            self._uid = j["uid"]
            self._key = j["key"]
            LOGGER.debug(
                f"SSCPOE cloud_login(email={self._email}): uid={self._uid}, key={self._key}"
            )
            self._uid_write = True

        if self.devices is None:
            if self.prj is None:
                j, err = self._session.cloud_request(
                    "prjmng", None, self._key, self._uid
                )
                if j is None:
                    if err == "dencrypt failed":
                        self._uid = None
                        self._uid_write = True
                    raise ApiError(
                        f"SSCPOE_cloud_request({self._email}, prjmng): {err}"
                    )
                self.prj = {}
                for p in j["admin"] + j["join"]:
                    pid = p["pid"]
                    self.prj[pid] = p
                    j, err = self._session.cloud_request(
                        "swmng", {"pid": pid}, self._key, self._uid
                    )
                    if j is None:
                        raise ApiError(
                            f"SSCPOE_cloud_request({self._email}, swmng): {err}"
                        )
                    p["online"] = j["online"]
            #                    p["offline"] = j["offline"]
            self.devices = {}
            for i, pid in enumerate(self.prj):
                p = self.prj[pid]
                for s in p["online"]:
                    sn = s["sn"]
                    self.devices[sn] = {"pid": pid, "sn": sn}
        #                for s in p["offline"]:
        #                    sn = s["sn"]
        #                    self.devices[sn] = {"pid": pid, "sn": sn}

        for i, sn in enumerate(self.devices):
            device = self.devices[sn]
            j, err = self._session.cloud_request(
                "swdet",
                {"pid": device["pid"], "sn": sn, "isJoin": "1"},
                self._key,
                self._uid,
            )
            if j is None:
                #                raise ApiError(f"SSCPOE_cloud_request({self._email}, swdet): {err}")
                device["detail"]["online"] = False
                continue
            detail = j["detail"]
            detail["online"] = True
            device["detail"] = detail
            if not ("device_info" in device):
                device["device_info"] = DeviceInfo(
                    identifiers={(DOMAIN, sn)},
                    manufacturer="STEAMEMO",
                    model=device.get("model", SSCPOE_model_from_sn(sn)),
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
        except Exception as ex:  # ApiError or TimeoutError
            if not self._email:  # Don't relogin the cloud account
                self._uid = None
                self._uid_write = True
            raise UpdateFailed(f"Error communicating with API: {str(ex)}")

    async def _async_switch_extend(
        self, pid: str, sn: str, index: int, extend: bool
    ) -> None:
        try:
            async with asyncio.timeout(10 if SSCPOE_Coordinator.is_cloud(pid) else 2):
                return await self.hass.async_add_executor_job(
                    self._switch_extend, pid, sn, index, extend
                )
        except Exception as ex:  # ApiError or TimeoutError
            if not self._email:  # Don't relogin the cloud account
                self._uid = None
                self._uid_write = True
            raise UpdateFailed(f"Error communicating with API: {str(ex)}")

    def _switch_poe(self, pid: str, sn: str, index: int, poec: bool) -> None:
        opcode = (0x202 if poec else 2) | (index << 4)
        errcode = self._switch(pid, sn, opcode)
        if errcode != 0:
            raise ApiError(f"_switch_poe: errcode={errcode}")

    def _switch_extend(self, pid: str, sn: str, index: int, extend: bool) -> None:
        # 0x200: phyc = 1: 10MBit half duplex
        # 0x400: phyc = 2: 10MBit full duplex
        # 0x800: phyc = 4: 100MBit full duplex
        # 0xA00: phyc = 5: 1GBit full duplex
        # 0xC00: err=1001 # GS105
        opcode = (0x400 if extend else 0xA00) | (index << 4)
        for i in range(2):
            errcode = self._switch(pid, sn, opcode)
            if errcode == 0:
                break
            if i == 0 and errcode == 1001:
                opcode = (0x200 if extend else 0x800) | (index << 4)
                continue
            raise ApiError(f"_switch_extend: errcode={errcode}")

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
            },
            self._ifname,
            self._ttl,
        )
        if j is None:
            raise ApiError("SSCPOE_local_request(config): {err}")
        return 0

    def _switch_web(self, opcode: int) -> int:
        if self._uid is None:
            return -1
        j, err = self._session.web_request(
            self._ip, self._uid, SSCPOE_web_cmd.set_poe_duplex, {"opcode": opcode}
        )
        if j is None:
            raise ApiError(
                f"SSCPOE_web_request({self._ip}, {SSCPOE_web_cmd.set_poe_duplex}, opcode: {opcode}) err={err}"
            )
        return 0

    def _switch_cloud(self, pid: str, sn: str, opcode: int) -> int:
        if self._uid is None:
            return -1
        swconf = {
            "pid": pid,
            "sn": sn,
            "opcode": opcode,
        }
        j, err = self._session.cloud_request("swconf", swconf, self._key, self._uid)
        if j is None:
            raise ApiError(f"SSCPOE_cloud_request({self._email}, swconf): {err}")
        errcode = int(j["data"]["errcode"])
        return errcode


class ApiError(HomeAssistantError):
    """ApiError"""


class ApiAuthError(HomeAssistantError):
    """ApiAuthError"""
