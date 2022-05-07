from __future__ import annotations

from pprint import pprint
from typing import Any, NamedTuple, Optional

from requests import get, post

from uc_sso.parsers import SSOHandshakeParser, SSOUserInfoParser

SSO_ENDPOINT = "https://sso.uc.cl/cas/login"

# Exceptions

class LoginFailed(Exception):
    def __init__(self, message: str):
        self.message = message


class SSOProtocolError(ConnectionError):
    pass

# Main data entities

class InitialHandshakeData(NamedTuple):
    """Stores the data (`ssosaf` and `execution`) needed to POST login data to the SSO."""

    ssosaf: str
    execution: str


class ServiceTicket(NamedTuple):
    """Stores the ticket (`value`) and authenticated URL (`service_url`) to access a service."""

    value: str
    service_url: str

# Now, to the fun stuff

def _get_initial_handshake(endpoint: str = SSO_ENDPOINT) -> InitialHandshakeData:
    """
    Returns the initial handshake data from the endpoint and the execution form parameter.

    The metadata returned (`ssosaf` and `execution`) is needed to authenticate subsequent requests to SSO endpoints.
    """
    response = get(endpoint)
    # Get the ssosaf parameter from the cookies
    ssosaf = response.cookies.get("ssosaf")
    if ssosaf is None:
        raise ValueError("Could not find ssosaf cookie.")
    # Parse the response to try to find the execution parameter
    html = response.text
    parser = SSOHandshakeParser()
    parser.feed(html)
    execution = parser.execution
    if execution is None:
        raise ValueError("Could not find execution parameter in response.")

    return InitialHandshakeData(ssosaf=ssosaf, execution=execution)


def get_user_info(
    username: str,
    password: str,
    handshake_data: Optional[InitialHandshakeData] = None,
    sso_endpoint: str = SSO_ENDPOINT,
) -> dict[str, Any] | None:
    """
    Logins to the main SSO endpoint using the given credentials and returns a dictionary of user attributes based on the default diagnostic response.

    Standard returned attributes:
    - `username` - username being used to login
    - `email` - the main identifying email
    - `alternate_emails` - a list of alternate emails used by the user
    - `email_type` - whether the user uses gmail, exchange, or other provider
    - `full_name` - the full combined name of the user
    - `given_name` - first name
    - `surnames` - the combined last names of the user
    - `first_last_name` - the first part of the last name (the normal last name)
    - `second_last_name` - the second last name used in spanish
    - `run` - the chilean Rol Único Nacional (RUN) of the person (e.g `12345678-9`)
    - `user_category` - the category of the user (student, teacher, etc)
    - `user_type` - number representing the category (1, 2, 3, etc)
    - `udc_id` - the internal user ID (e.g. `A1EC2KD3432909R67FSD89`)

    The attributes CANNOT be guaranteed to be present in the response, and their keys don't necessarily match the keys in the response, as they're internally rewritten for convenience.

    Raises a `LoginFailed` exception if the credentials are invalid, or a `SSOProtocolError` if the SSO doesn't respond as expected.
    
    """
    if handshake_data is None:
        handshake_data = _get_initial_handshake(sso_endpoint)

    response = post(
        sso_endpoint,
        {
            "username": username,
            "password": password,
            "_eventId": "submit",
            "execution": handshake_data.execution,
        },
        cookies={"ssosaf": handshake_data.ssosaf},
    )
    if response.status_code != 200:
        raise SSOProtocolError(
            f"SSO didn't respond to information request as expected (HTTP {response.status_code})."
        )

    html = response.text
    parser = SSOUserInfoParser()
    parser.feed(html)
    if parser.login_status == "failure":
        raise LoginFailed("Invalid credentials.")

    return parser.attributes


def get_ticket(
    username: str, password: str, service_url: str, sso_endpoint: str = SSO_ENDPOINT
) -> ServiceTicket:
    """
    Gets a ticket object in order to authenticate requests to a service (`service_url`) through the centralized CAS system.
    
    The ticket returned can be used directly (using the `value` attribute) to authenticate requests to the service by embedding it in the request URL, but it's also possible to use the `service_url` attribute to authenticate requests to the service more easily.

    Receives an optional `sso_endpoint` parameter to use a different endpoint than the default used in UC Chile (`https://sso.uc.cl/cas/login`).

    Raises a `LoginFailed` exception if the credentials are invalid, or a `SSOProtocolError` if the SSO doesn't respond as expected.
    """
    initial_service_response = get(service_url, allow_redirects=False)
    if initial_service_response.status_code not in (200, 302):
        raise ConnectionError(
            f"Could not reach service. Status code: {initial_service_response.status_code}"
        )
    if not initial_service_response.is_redirect:
        raise SSOProtocolError("Service doesn't seem to be SSO protected.")

    sso_redirect_url = initial_service_response.headers.get("Location")
    assert sso_redirect_url, "Could not find SSO redirect URL."

    # Get the handshake data from the redirect url
    handshake_data = _get_initial_handshake(sso_redirect_url)
    login_response = post(
        sso_redirect_url,
        {
            "username": username,
            "password": password,
            "_eventId": "submit",
            "execution": handshake_data.execution,
        },
        cookies={"ssosaf": handshake_data.ssosaf},
        allow_redirects=False,
    )
    if not login_response.is_redirect:
        raise SSOProtocolError(
            f"The second-step handshake didn't present a redirect (HTTP {login_response.status_code})."
        )

    # Get the ticket from the login response
    ticketed_service_url = login_response.headers.get("Location")
    assert ticketed_service_url is not None, "Could not get ticketed service url."

    ticket = ticketed_service_url.split("ticket=")[1]
    return ServiceTicket(ticket, ticketed_service_url)


if __name__ == "__main__":
    username, password = input("Username: "), input("Passsword: ")
    handshake_info = _get_initial_handshake()
    print("Obtained handshake data: ")
    pprint(handshake_info)
    print()
    user_info = get_user_info(username, password, handshake_info)
    print("Obtained user info: ")
    pprint(user_info)
    print()
    ticket = get_ticket(username, password, "https://portal.uc.cl")
    print("Obtained ticket: ")
    pprint(ticket)
