from __future__ import annotations

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigEntry, CONN_CLASS_CLOUD_POLL
from homeassistant.const import CONF_ID, CONF_EMAIL, CONF_PASSWORD
from .const import DOMAIN, LOGGER
from .protocol import (
    SSCPOE_local_search,
    SSCPOE_local_login,
    SSCPOE_cloud_login,
)


class SSCPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 4

    # CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL

    local_devices: list[dict] = None

    async def async_step_user(self, user_input: dict[str, str] = None) -> FlowResult:
        if user_input:
            if user_input["action"] == "cloud":
                return await self.async_step_cloud()
            else:
                sn = user_input["action"]
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
        actions = {"cloud": "Add SSCPOE cloud account"}
        for device in self.local_devices:
            activate = " Not activated!" if device["Active_state"] != "active" else ""
            actions[device["sn"]] = (
                f"Add {device['model']}, S/N: {device['sn']} ({device['ip']}){activate}"
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
            if len(password) != 6 or not password.isdigit():
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
            pass_len = len(password)
            if pass_len < 6 or pass_len > 12:
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

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Handle re-authentication."""
        self.entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, str] = None
    ) -> FlowResult:
        """Confirm re-authentication"""
        errors: dict[str, str] = {}
        sn = self.entry.data.get(CONF_ID)
        if user_input:
            sn = user_input.get(CONF_ID, sn)
            email = user_input.get(CONF_EMAIL, None)
            password = user_input[CONF_PASSWORD]
            if sn:
                if len(password) != 6 or not password.isdigit():
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
                        self.hass.config_entries.async_update_entry(
                            self.entry,
                            data={
                                **self.entry.data,
                                CONF_ID: sn,
                                CONF_PASSWORD: password,
                            },
                        )
                        await self.hass.config_entries.async_reload(self.entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
            else:
                pass_len = len(password)
                if pass_len < 6 or pass_len > 12:
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
                        self.hass.config_entries.async_update_entry(
                            self.entry,
                            data={
                                **self.entry.data,
                                CONF_EMAIL: email,
                                CONF_PASSWORD: password,
                            },
                        )
                        await self.hass.config_entries.async_reload(self.entry.entry_id)
                        return self.async_abort(reason="reauth_successful")

        if sn:
            data_schema = vol.Schema(
                {
                    vol.Required(CONF_ID, default=sn): str,
                    vol.Required(
                        CONF_PASSWORD, default=password if user_input else None
                    ): str,
                }
            )
        else:
            data_schema = vol.Schema(
                {
                    vol.Required(
                        CONF_EMAIL, default=email if user_input else None
                    ): str,
                    vol.Required(
                        CONF_PASSWORD, default=password if user_input else None
                    ): str,
                }
            )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=data_schema,
            errors=errors,
        )
