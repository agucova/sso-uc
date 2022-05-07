from __future__ import annotations
from multiprocessing.connection import Connection

from pprint import pprint
from typing import NamedTuple, Optional

from requests import get, post

from uc_sso.parsers import SSOHandshakeParser, SSOUserInfoParser

SSO_ENDPOINT = "https://sso.uc.cl/cas/login"


class LoginFailed(Exception):
    def __init__(self, message: str):
        self.message = message

class SSOProtocolError(ConnectionError):
    pass


class InitialHandshakeData(NamedTuple):
    """Stores the data needed to POST login data to the SSO."""

    ssosaf: str
    execution: str


class ServiceTicket(NamedTuple):
    """Stores the ticket and authenticated URL to a service."""

    value: str
    service_url: str


def get_initial_handshake(endpoint: str = SSO_ENDPOINT) -> InitialHandshakeData:
    """Returns the initial handshake data from the endpoint and the execution form parameter."""
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
):
    "Tries to login to the SSO using the given credentials and returns a dictionary of user attributes based on the default response."
    if handshake_data is None:
        handshake_data = get_initial_handshake(sso_endpoint)

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
        raise SSOProtocolError(f"SSO didn't respond to information request as expected (HTTP {response.status_code}).")

    html = response.text
    parser = SSOUserInfoParser()
    parser.feed(html)
    if parser.login_status == "failure":
        raise LoginFailed("Invalid credentials.")

    return parser.attributes


def get_ticket(
    username: str, password: str, service_url: str, sso_endpoint: str = SSO_ENDPOINT
) -> ServiceTicket:
    """Gets a ticket and an authenticated url to access a given service."""
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
    handshake_data = get_initial_handshake(sso_redirect_url)
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
    handshake_info = get_initial_handshake()
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
