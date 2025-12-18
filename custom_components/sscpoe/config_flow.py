from __future__ import annotations

import voluptuous as vol
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
)
from homeassistant.config_entries import ConfigFlow, ConfigEntry, CONN_CLASS_CLOUD_POLL
from homeassistant.const import (
    CONF_ID,
    CONF_IP_ADDRESS,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_IF,
    CONF_TTL,
)
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_local_search,
    SSCPOE_local_login,
    SSCPOE_cloud_login,
    SSCPOE_web_login,
    SSCPOE_web_accessibility,
    SSCPOE_LOCAL_DEF_PASSWORD,
    SSCPOE_LOCAL_DEF_BIND_INTERFACE,
    SSCPOE_LOCAL_DEF_TTL,
    SSCPOE_get_interfaces,
)


def bad_password(password):
    pass_len = len(password)
    return pass_len < 6 or pass_len > 12


STEP_USER = "user"
STEP_WEB = "web"
STEP_CLOUD = "cloud"
STEP_SEARCH = "search"
STEP_SELECT_IF = "select_if"
STEP_REAUTH = "reauth_confirm"

ACTION = "action"
ACTION_WEB = "web"
ACTION_CLOUD = "cloud"
ACTION_SEARCH = "search"
ACTION_SELECT_IF = "select_if"


class SSCPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 4

    # CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL

    local_devices: list[dict] = None
    interfaces: list[str] = None
    ifname: str = SSCPOE_LOCAL_DEF_BIND_INTERFACE
    ttl: int = SSCPOE_LOCAL_DEF_TTL

    async def async_step_user(self, user_input: dict[str, str] = None) -> FlowResult:
        if user_input:
            action = user_input[ACTION]
            if action == ACTION_SELECT_IF:
                return await self.async_step_select_if()
            elif action == ACTION_WEB:
                return await self.async_step_web()
            elif action == ACTION_CLOUD:
                return await self.async_step_cloud()
            return self.async_abort(reason="unknown")

        actions = {
            ACTION_SELECT_IF: "Auto search local SSCPOE devices",
            ACTION_WEB: "Add SSCPOE WEB device manually",
            ACTION_CLOUD: "Add SSCPOE cloud account",
        }
        return self.async_show_form(
            step_id=STEP_USER,
            data_schema=vol.Schema(
                {vol.Required(ACTION, default=ACTION_SELECT_IF): vol.In(actions)}
            ),
        )

    async def async_step_select_if(
        self, user_input: dict[str, str] = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if self.interfaces is None:
            self.interfaces = SSCPOE_get_interfaces()

        if user_input:
            self.ifname = str(user_input[CONF_IF]).split(" (")[
                0
            ]  # Extract interface name w/o (IP)
            self.ttl = int(user_input[CONF_TTL])
            return await self.async_step_search()

        return self.async_show_form(
            step_id=STEP_SELECT_IF,
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_IF, default=self.ifname): vol.In(self.interfaces),
                    vol.Required(CONF_TTL, default=self.ttl): NumberSelector(
                        NumberSelectorConfig(
                            min=1,
                            max=255,
                            mode=NumberSelectorMode.BOX,  # This ensures display as a text input field
                        )
                    ),
                }
            ),
        )

    async def async_step_search(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input:
            action = user_input[ACTION]
            if action == ACTION_SELECT_IF:
                return await self.async_step_select_if()
            elif action == ACTION_SEARCH:
                pass
            elif action.startswith("web_"):
                ip = action[4:]
                return self.async_show_form(
                    step_id=STEP_WEB,
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_IP_ADDRESS, default=ip): str,
                            vol.Required(
                                CONF_PASSWORD, default=SSCPOE_LOCAL_DEF_PASSWORD
                            ): str,
                        }
                    ),
                )
            else:
                sn = action
                return self.async_show_form(
                    step_id="local",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_ID, default=sn): str,
                            vol.Required(
                                CONF_PASSWORD, default=SSCPOE_LOCAL_DEF_PASSWORD
                            ): str,
                        }
                    ),
                )

        self.local_devices = await self.hass.async_add_executor_job(
            SSCPOE_local_search, self.ifname, self.ttl
        )
        actions = {
            ACTION_SEARCH: "Search again",
            ACTION_SELECT_IF: "Change interface or TTL",
        }
        for device in self.local_devices:
            sn = device["sn"]
            ip = device["ip"]
            # Note SSCPOE_local_search() must normalize the device data, including the model.
            model = device["model"]
            fw = device.get("V")
            if fw:
                model += f" (FW {fw})"
            activate = "Not activated! " if device["Active_state"] != "active" else ""
            is_web = await self.hass.async_add_executor_job(
                SSCPOE_web_accessibility, ip
            )
            if is_web:
                actions["web_" + ip] = f"Add WEB {activate}{model}, {ip}, S/N: {sn}"
            actions[sn] = f"Add old API {activate}{model}, {ip}, S/N: {sn}"

        if not self.local_devices:
            errors["base"] = "no_devices"

        return self.async_show_form(
            step_id=STEP_SEARCH,
            data_schema=vol.Schema(
                {vol.Required(ACTION, default=ACTION_SEARCH): vol.In(actions)}
            ),
            errors=errors,
        )

    async def async_step_local(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        sn = ""
        password = SSCPOE_LOCAL_DEF_PASSWORD
        if user_input:
            sn = user_input[CONF_ID]
            password = user_input[CONF_PASSWORD]
            if bad_password(password):
                errors[CONF_PASSWORD] = "invalid_local_password"
            else:

                def login():
                    return SSCPOE_local_login(sn, password, "login", self.ifname, self.ttl)

                def activate():
                    return SSCPOE_local_login(sn, password, "activate", self.ifname, self.ttl)

                device = next(i for i in self.local_devices if i["sn"] == sn)
                if device["Active_state"] != "active":
                    err = await self.hass.async_add_executor_job(activate)
                else:
                    err = await self.hass.async_add_executor_job(login)
                if err:
                    errors["base"] = err
                else:
                    new_data = user_input.copy()
                    new_data[CONF_IF] = self.ifname
                    new_data[CONF_TTL] = self.ttl
                    return self.async_create_entry(title=sn, data=new_data)

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
        email = ""
        password = SSCPOE_LOCAL_DEF_PASSWORD
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
            step_id=STEP_CLOUD,
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL, default=email): str,
                    vol.Required(CONF_PASSWORD, default=password): str,
                }
            ),
            errors=errors,
        )

    async def async_step_web(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
        ip = ""
        password = SSCPOE_LOCAL_DEF_PASSWORD
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
            step_id=STEP_WEB,
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
        ifname = self.entry.data.get(CONF_IF, SSCPOE_LOCAL_DEF_BIND_INTERFACE)
        ttl = self.entry.data.get(CONF_TTL, SSCPOE_LOCAL_DEF_TTL)
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
                        res = SSCPOE_local_login(sn, password, "activate", ifname, ttl)
                        if res:
                            res = SSCPOE_local_login(sn, password, "login", ifname, ttl)
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
            step_id=STEP_REAUTH,
            data_schema=data_schema,
            errors=errors,
        )
