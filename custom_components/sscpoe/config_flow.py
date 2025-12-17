from __future__ import annotations
import socket
from typing import Any, Mapping
import voluptuous as vol
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import NumberSelector, NumberSelectorConfig, NumberSelectorMode
from homeassistant.config_entries import ConfigFlow, ConfigEntry, CONN_CLASS_CLOUD_POLL
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.const import (
    CONF_ID,
    CONF_IP_ADDRESS,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_TOKEN,
)
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_LOCAL_DEF_PASSWORD,
    SSCPOE_local_search,
    _get_ipv4_for_interface,
    SSCPOE_local_login,
    SSCPOE_cloud_login,
    SSCPOE_web_login,
    SSCPOE_web_request,
)


def bad_password(password):
    pass_len = len(password)
    return pass_len < 6 or pass_len > 12

CONF_METHOD = "method"
METHOD_CLOUD = "cloud"
METHOD_LOCAL_WEB = "local_web"
METHOD_LOCAL_MULTICAST = "local_multicast"

CONF_BIND_INTERFACE = "bind_interface"
#CONF_SET_TTL = "set_ttl"
CONF_MCAST_TTL = "mcast_ttl"
DEFAULT_BIND_INTERFACE = "default"


class SSCPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 4

    # CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL

    local_devices: list[dict] = None
    entry: ConfigEntry | None = None

    def _extract_model_from_sn(self, sn: str | None) -> str:
        """Extract model from first 10 chars of SN, strip trailing zeros."""
        if not sn or len(sn) < 10:
            return "Unknown"
        model = sn[:10].rstrip('0')
        return model if len(model) >= 3 else "Unknown"

    def _normalize_device_data(self, device: dict) -> dict:
        """Ensure all expected fields are present and consistent across discovery methods."""
        sn = device.get("sn")

        # Always extract model from SN for consistency, even if 'model' exists
        device["model"] = self._extract_model_from_sn(sn)

        # Firmware version
        firmware = device.get("V", "Unknown")
        if firmware and firmware not in ("Unknown", "0.0.0", "null", ""):
            device["model"] = f"{device['model']} (FW: {firmware})"

        # Ensure active state
        if "Active_state" not in device:
            device["Active_state"] = "active"

        return device

    async def async_step_user(self, user_input: dict[str, str] = None) -> FlowResult:
        """Screen 1: choose connection method."""
        if user_input:
            method = user_input[CONF_METHOD]
            if method == METHOD_CLOUD:
                return await self.async_step_cloud()
            if method == METHOD_LOCAL_WEB:
                return await self.async_step_local_web()
            if method == METHOD_LOCAL_MULTICAST:
                return await self.async_step_local_multicast()
            return self.async_abort(reason="unknown")

        methods = {
            METHOD_CLOUD: "Cloud",
            METHOD_LOCAL_WEB: "Local (Web)",
            METHOD_LOCAL_MULTICAST: "Local (Multicast)",
        }
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_METHOD, default=METHOD_CLOUD): vol.In(methods)}
            ),
        )

    async def async_step_local(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        sn = None
        password = "123456"
        if user_input:
            sn = user_input[CONF_ID]
            password = user_input[CONF_PASSWORD]
            if bad_password(password):
                errors[CONF_PASSWORD] = "invalid_local_password"
            else:

                def login():
                    return SSCPOE_local_login(sn, password)

                def activate():
                    return SSCPOE_local_login(sn, password, "activate")

                device = next((i for i in (self.local_devices or []) if i.get("sn") == sn), None)
                if not device:
                    errors["base"] = "device_not_found"
                else:
                    if device.get("Active_state") != "active":
                        err = await self.hass.async_add_executor_job(activate)
                    else:
                        err = await self.hass.async_add_executor_job(login)
                    if err:
                        errors["base"] = err
                    else:
                        return self.async_create_entry(title=sn, data=user_input)

        return self.async_show_form(
            step_id="local",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ID, default=sn): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            ),
            errors=errors,
        )

    async def async_step_cloud(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        email = None
        password = "123456"
        if user_input:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]
            if bad_password(password):
                errors[CONF_PASSWORD] = "invalid_cloud_password"
            elif len(email) < 3:
                errors[CONF_EMAIL] = "invalid_email"
            else:

                def login():
                    return SSCPOE_cloud_login(email, password)

                err = await self.hass.async_add_executor_job(login)
                if err:
                    errors["base"] = err
                else:
                    return self.async_create_entry(title=email, data=user_input)

        # If there is no user input or there were errors,
        # show the form again, including any errors that were found with the input.
        return self.async_show_form(
            step_id="cloud",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=email): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            ),
            errors=errors,
        )
        
        
    async def async_step_local_web(self, user_input: dict[str, str] = None) -> FlowResult:
        """Screen 2W: web credentials check, then go to local confirm screen."""
        errors: dict[str, str] = {}
        ip = None
        password = "123456"
    
        if user_input:
            ip = user_input[CONF_IP_ADDRESS]
            password = user_input[CONF_PASSWORD]
            if bad_password(password):
                errors[CONF_PASSWORD] = "invalid_web_password"
            elif len(ip) < 7 or len(ip.split(".")) != 4:
                errors[CONF_IP_ADDRESS] = "invalid_ip"
            else:
    
                devices = [{"ip": ip}]
                await self._check_web_accessibility(devices)
                device = devices[0]
                
                if not device.get("web_token"):
                    errors["base"] = "web_login_failed"
                else:
                    # Fetch real device data via callcmd=101
                    try:
                        device_info, err = await self.hass.async_add_executor_job(
                            SSCPOE_web_request, ip, device["web_token"], 101
                        )
                        if not err and device_info and "calldata" in device_info:
                            calldata = device_info["calldata"]
                            sn = calldata.get("sn", f"web_{ip.replace('.', '_')}")
                            
                            # Extract model from first 10 characters of SN
                            if sn and len(sn) >= 10:
                                model_prefix = sn[:10]
                                model = model_prefix.rstrip('0')  # Remove trailing zeros
                                if len(model) >= 3:  # Ensure minimum length
                                    pass  # model is already valid
                                else:
                                    model = "Unknown"
                            else:
                                model = "Unknown"
                                
                            # Firmware version
                            firmware = calldata.get("V", "Unknown")
                        else:
                            sn = f"web_{ip.replace('.', '_')}"
                            model = "Unknown"
                            firmware = "Unknown"
                    except Exception as e:
                        LOGGER.debug("Failed to get device info for %s: %s", ip, e)
                        sn = f"web_{ip.replace('.', '_')}"
                        model = "Unknown"
                        firmware = "Unknown"

                    # Build single-item list using unified logic
                    self.local_devices = [
                        self._normalize_device_data({
                            "ip": ip,
                            "sn": sn,
                            "V": firmware,
                            "Active_state": "active",
                            "web_token": device["web_token"],
                            "add_method": "web",
                            "user_password": password
                        })
                    ]
                    return await self.async_step_local_select()
    
        return self.async_show_form(
            step_id="local_web",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_IP_ADDRESS, default=ip): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            ),
            errors=errors,
        )
    
    async def async_step_local_multicast(self, user_input: dict[str, Any] = None) -> FlowResult:
        """Screen 2M: multicast discovery settings + scan, then go to local confirm screen."""
        errors: dict[str, str] = {}
    
        # Get list of interfaces with their IP addresses
        iface_choices = self._get_interface_choices()
        if not iface_choices:
            errors["base"] = "no_interfaces_with_ip"
            return self.async_show_form(
                step_id="local_multicast",
                data_schema=vol.Schema({}),
                errors=errors,
            )        
        
        bind_default = DEFAULT_BIND_INTERFACE
        set_ttl_default = False
        ttl_default = 2
    
        if user_input:
            bind_iface = str(user_input.get(CONF_BIND_INTERFACE, DEFAULT_BIND_INTERFACE))
            #set_ttl = bool(user_input.get(CONF_SET_TTL, False))
            ttl = int(user_input.get(CONF_MCAST_TTL, ttl_default))

            bind_iface_param = None if bind_iface == DEFAULT_BIND_INTERFACE else bind_iface.split(" (")[0]  # Extract interface name without IP
    
            try:
                discovered = await self.hass.async_add_executor_job(
                    SSCPOE_local_search, bind_iface_param, ttl
                )
            except Exception as e:
                LOGGER.exception("SSCPOE multicast discovery failed: %s", e)
                errors["base"] = "multicast_discovery_failed"
            else:
                if not discovered:
                    errors["base"] = "multicast_discovery_timeout"
                else:
                    self.local_devices = []
                    web_candidates = []
                    # Process each discovered device with normalization
                    for dev in discovered:
                         old_device = self._normalize_device_data({
                             "add_method": "old",
                             "sn": dev.get("sn"),
                             "ip": dev.get("ip"),
                             "V": dev.get("V"),
                             "Active_state": dev.get("Active_state", "active"),
                         })
                         self.local_devices.append(old_device)
    
                         # Add to web candidate list if IP is set
                         if dev.get("ip"):
                             web_candidates.append({"ip": dev["ip"]})

                     # Check web accessibility for all candidates
                    if web_candidates:
                         await self._check_web_accessibility(web_candidates)
    
                     # Add web devices to local_devices
                    for candidate in web_candidates:
                         if candidate.get("web_token"):
                             ip = candidate["ip"]
                             # Find existing device with this IP
                             src_dev = next((d for d in self.local_devices if d["ip"] == ip and d["add_method"] == "old"), None)
                             if src_dev:
                                 web_device = self._normalize_device_data({
                                     "add_method": "web",
                                     "ip": ip,
                                     "sn": src_dev["sn"],
                                     "V": src_dev["V"],
                                     "Active_state": "active",
                                     "web_token": candidate["web_token"],
                                     "user_password": SSCPOE_LOCAL_DEF_PASSWORD,
                                 })
                                 self.local_devices.append(web_device)

                    return await self.async_step_local_select()

            bind_default = bind_iface
            ttl_default = ttl
    
        schema_dict: dict = {
            vol.Required(CONF_BIND_INTERFACE, default=bind_default): vol.In(iface_choices),
            vol.Required(CONF_MCAST_TTL, default=ttl_default): NumberSelector(
                NumberSelectorConfig(
                    min=1,
                    max=255,
                    mode=NumberSelectorMode.BOX  # This ensures display as a text input field
                )
            ),
        }   
   
        return self.async_show_form(
            step_id="local_multicast",
            data_schema=vol.Schema(schema_dict),
            errors=errors,
        )    
    
    async def _check_web_accessibility(self, devices: list[dict]) -> None:
        """Check HTTP management accessibility with default password for devices."""
        
        for device in devices:
            ip = device.get("ip")
            if not ip:
                continue
                
            try:
                # Use the same method as in async_step_local_web
                err, token = await self.hass.async_add_executor_job(
                    SSCPOE_web_login, ip, SSCPOE_LOCAL_DEF_PASSWORD
                )
                if not err:
                    # Add token for further use
                    device["web_token"] = token
                else:
                    LOGGER.debug("SSCPOE HTTP access check failed for %s: %s", ip, err)
            except Exception as e:
                LOGGER.debug("SSCPOE HTTP access check exception for %s: %s", ip, e)
                
        return None
    
    def _get_interface_choices(self) -> list[str]:
        """Get list of interfaces with their IP addresses, hiding interfaces without IP."""
        try:
            interfaces = []
            for idx, name in socket.if_nameindex():
                ip = _get_ipv4_for_interface(name)
                if ip:
                    interfaces.append(f"{name} ({ip})")
            return [DEFAULT_BIND_INTERFACE] + sorted(interfaces)
        except Exception:
            return [DEFAULT_BIND_INTERFACE]

    async def async_step_local_select(self, user_input: dict[str, str] = None) -> FlowResult:
        """Screen 3L: confirm/choose local device to add (web/manual or multicast)."""
        if user_input:
            action = user_input["action"]
    
            if action.startswith("web_"):
                ip = action[4:]
    
                # Otherwise (multicast), go through normal web step with prefilled IP
                return self.async_show_form(
                    step_id="web",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_IP_ADDRESS, default=ip): str,
                            vol.Required(CONF_PASSWORD, default="123456"): str,
                        }
                    ),
                )
    
            # old API by SN (or fallback ip)
            if action.startswith("old_"):
                sn = action[4:]
                return self.async_show_form(
                    step_id="local",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_ID, default=sn): str,
                            vol.Required(CONF_PASSWORD, default="123456"): str,
                        }
                    ),
                )
            
            return self.async_abort(reason="unknown_action")
    
        actions = {}
        for device in (self.local_devices or []):
            if device.get("add_method") == "old":
                sn = device.get("sn") or device.get("ip", "unknown")
                activate = " Not activated!" if device.get("Active_state") != "active" else ""
                actions[f"old_{sn}"] = f"Add old API {device.get('model','Unknown')}, S/N: {sn} ({device['ip']}){activate}"

            elif device.get("add_method") == "web":
                ip = device["ip"]
                sn = device.get("sn") or f"web_{ip.replace('.', '_')}"
                actions[f"web_{ip}"] = f"Add WEB {device.get('model','Unknown')}, S/N: {sn} ({ip})"
    
        return self.async_show_form(
            step_id="local_select",
            data_schema=vol.Schema({vol.Required("action"): vol.In(actions)}),
        )
    
    
    async def async_step_web(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        ip = None
        password = "123456"
        if user_input:
            ip = user_input[CONF_IP_ADDRESS]
            password = user_input[CONF_PASSWORD]
            if bad_password(password):
                errors[CONF_PASSWORD] = "invalid_web_password"
            elif len(ip) < 7 or len(ip.split(".")) != 4:
                errors[CONF_IP_ADDRESS] = "invalid_ip"
            else:

                def login():
                    return SSCPOE_web_login(ip, password)

                err, token = await self.hass.async_add_executor_job(login)
                if err:
                    errors["base"] = err
                else:
                    user_input[CONF_TOKEN] = token
                    return self.async_create_entry(title=ip, data=user_input)

        # If there is no user input or there were errors,
        # show the form again, including any errors that were found with the input.
        return self.async_show_form(
            step_id="web",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_IP_ADDRESS, default=ip): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Handle re-authentication."""
        self.entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, str] = None
    ) -> FlowResult:
        """Confirm re-authentication"""
        errors: dict[str, str] = {}
        if not self.entry:
            return self.async_abort(reason="missing_entry")
        sn = self.entry.data.get(CONF_ID, None)
        ip = self.entry.data.get(CONF_IP_ADDRESS, None)
        email = self.entry.data.get(CONF_EMAIL, None)
        password = self.entry.data.get(CONF_PASSWORD, None)
        token = self.entry.data.get(CONF_TOKEN, None)
        if user_input:
            sn = user_input.get(CONF_ID, sn)
            ip = user_input.get(CONF_IP_ADDRESS, ip)
            email = user_input.get(CONF_EMAIL, email)
            password = user_input.get(CONF_PASSWORD, password)
            if sn:
                if bad_password(password):
                    errors[CONF_PASSWORD] = "invalid_local_password"
                else:

                    def login():
                        res = SSCPOE_local_login(sn, password, "activate")
                        if res:
                            res = SSCPOE_local_login(sn, password)
                        return res

                    err = await self.hass.async_add_executor_job(login)
                    if err:
                        errors["base"] = err
                    else:
                        assert self.entry is not None
                        new_data = {**self.entry.data}
                        new_data[CONF_ID] = sn
                        new_data[CONF_PASSWORD] = password
                        self.hass.config_entries.async_update_entry(
                            self.entry,
                            data=new_data,
                        )
                        await self.hass.config_entries.async_reload(self.entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
            elif ip:
                if bad_password(password):
                    errors[CONF_PASSWORD] = "invalid_web_password"
                else:

                    def login():
                        return SSCPOE_web_login(ip, password, token)

                    err, token = await self.hass.async_add_executor_job(login)
                    if err:
                        errors["base"] = err
                    else:
                        assert self.entry is not None
                        new_data = {**self.entry.data}
                        new_data[CONF_IP_ADDRESS] = ip
                        new_data[CONF_PASSWORD] = password
                        new_data[CONF_TOKEN] = token
                        self.hass.config_entries.async_update_entry(
                            self.entry,
                            data=new_data,
                        )
                        await self.hass.config_entries.async_reload(self.entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
            else:
                if bad_password(password):
                    errors[CONF_PASSWORD] = "invalid_cloud_password"
                elif len(email) < 3:
                    errors[CONF_EMAIL] = "invalid_email"
                else:

                    def login():
                        return SSCPOE_cloud_login(email, password)

                    err = await self.hass.async_add_executor_job(login)
                    if err:
                        errors["base"] = err
                    else:
                        assert self.entry is not None
                        new_data = {**self.entry.data}
                        new_data[CONF_EMAIL] = email
                        new_data[CONF_PASSWORD] = password
                        self.hass.config_entries.async_update_entry(
                            self.entry,
                            data=new_data,
                        )
                        await self.hass.config_entries.async_reload(self.entry.entry_id)
                        return self.async_abort(reason="reauth_successful")

        if sn:
            data_schema = vol.Schema(
                {
                    vol.Required(CONF_ID, default=sn): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            )
        elif ip:
            data_schema = vol.Schema(
                {
                    vol.Required(CONF_IP_ADDRESS, default=ip): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            )
        else:
            data_schema = vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=email): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=data_schema,
            errors=errors,
        )
