from __future__ import annotations

import hashlib
import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigEntry, CONN_CLASS_CLOUD_POLL
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from .const import DOMAIN, LOGGER
from .protocol import SSCPOE_KEY, SSCPOE_request


class SSCPOE_ConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    CONNECTION_CLASS = CONN_CLASS_CLOUD_POLL

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]
            pass_len = len(password)
            if pass_len < 6 or pass_len > 12:
                errors[CONF_PASSWORD] = "invalid_password"
            elif len(email) < 3:
                errors[CONF_EMAIL] = "invalid_email"
            else:

                def login():
                    eml = {
                        "email": email,
                        "pd": hashlib.md5(password.encode("utf-8")).hexdigest(),
                    }
                    j = SSCPOE_request("eml", eml, SSCPOE_KEY, None)
                    if j is None:
                        return "unknown"
                    errcode = j["errcode"]
                    if errcode == -1:
                        return "cannot_connect"
                    elif errcode == 20003:
                        return "wrong_email"
                    elif errcode == 20004:
                        return "wrong_password"
                    elif errcode != 0:
                        return f"invalid auth code {errcode}"
                    return None

                err = await self.hass.async_add_executor_job(login)
                if err:
                    errors["base"] = err
                else:
                    return self.async_create_entry(title=email, data=user_input)

        # If there is no user input or there were errors,
        # show the form again, including any errors that were found with the input.
        return self.async_show_form(
            step_id="user",
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
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Confirm re-authentication"""
        errors: dict[str, str] = {}
        if user_input:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]
            pass_len = len(password)
            if pass_len < 6 or pass_len > 12:
                errors[CONF_PASSWORD] = "invalid_password"
            elif len(email) < 3:
                errors[CONF_EMAIL] = "invalid_email"
            else:

                def login():
                    eml = {
                        "email": email,
                        "pd": hashlib.md5(password.encode("utf-8")).hexdigest(),
                    }
                    j = SSCPOE_request("eml", eml, SSCPOE_KEY, None)
                    if j is None:
                        return "unknown"
                    errcode = j["errcode"]
                    if errcode == -1:
                        return "cannot_connect"
                    elif errcode == 20003:
                        return "wrong_email"
                    elif errcode == 20004:
                        return "wrong_password"
                    elif errcode != 0:
                        return f"invalid auth code {errcode}"
                    return None

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

        return self.async_show_form(
            step_id="reauth_confirm",
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
