from __future__ import annotations

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigEntry, CONN_CLASS_CLOUD_POLL
from homeassistant.const import (
    CONF_ID,
    CONF_IP_ADDRESS,
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_TOKEN,
)
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_local_search,
    SSCPOE_local_login,
    SSCPOE_cloud_login,
    SSCPOE_web_login,
)


def bad_password(password):
    pass_len = len(password)
    return pass_len < 6 or pass_len > 12


class SSCPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 4

    # CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL

    local_devices: list[dict] = None

    async def async_step_user(self, user_input: dict[str, str] = None) -> FlowResult:
        if user_input:
            action = user_input["action"]
            if action == "cloud":
                return await self.async_step_cloud()
            elif action == "web":
                return await self.async_step_web()
            elif action.startswith("web_"):
                ip = action[4:]
                return self.async_show_form(
                    step_id="web",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_IP_ADDRESS, default=ip): str,
                            vol.Required(CONF_PASSWORD, default="123456"): str,
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
                            vol.Required(CONF_PASSWORD, default="123456"): str,
                        }
                    ),
                )

        self.local_devices = await self.hass.async_add_executor_job(SSCPOE_local_search)
        actions = {
            "cloud": "Add SSCPOE cloud account",
            "web": "Add SSCPOE WEB device manually",
        }
        for device in self.local_devices:
            actions["web_" + device["ip"]] = (
                f"Add WEB {device['model']}, S/N: {device['sn']} ({device['ip']})"
            )
            activate = " Not activated!" if device["Active_state"] != "active" else ""
            actions[device["sn"]] = (
                f"Add old API {device['model']}, S/N: {device['sn']} ({device['ip']}){activate}"
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required("action", default="cloud"): vol.In(actions)}
            ),
        )

    async def async_step_local(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
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

                device = next(i for i in self.local_devices if i["sn"] == sn)
                if device["Active_state"] != "active":
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
                    vol.Required(CONF_ID, default=sn if user_input else None): str,
                    vol.Required(
                        CONF_PASSWORD, default=password if user_input else None
                    ): str,
                }
            ),
            errors=errors,
        )

    async def async_step_cloud(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
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
                    vol.Required(
                        CONF_EMAIL, default=email if user_input else None
                    ): str,
                    vol.Required(
                        CONF_PASSWORD, default=password if user_input else None
                    ): str,
                }
            ),
            errors=errors,
        )

    async def async_step_web(self, user_input: dict[str, str] = None) -> FlowResult:
        errors: dict[str, str] = {}
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
                    vol.Required(
                        CONF_IP_ADDRESS, default=ip if user_input else None
                    ): str,
                    vol.Required(
                        CONF_PASSWORD, default=password if user_input else None
                    ): str,
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
