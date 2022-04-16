from __future__ import annotations

from html.parser import HTMLParser
from pprint import pprint
from typing import Any, Literal, NamedTuple, Optional

from html_table_parser.parser import HTMLTableParser
from requests import get, post

SSO_ENDPOINT = "https://sso.uc.cl/cas/login"


class LoginFailed(Exception):
    def __init__(self, message: str):
        self.message = message


class InitialHandshakeData(NamedTuple):
    """Stores the data needed to POST login data to the SSO."""

    ssosaf: str
    execution: str


class ServiceTicket(NamedTuple):
    """Stores the ticket and authenticated URL to a service."""

    value: str
    service_url: str


class SSOHandshakeParser(HTMLParser):
    """Parses the login form from the SSO to get the data needed for the initial handshake."""

    def __init__(self):
        super().__init__()
        self.execution: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            if ("name", "execution") in attrs:
                for name, value in attrs:
                    if name == "value":
                        self.execution = value
                        break


class SSOUserInfoParser(HTMLTableParser):
    """Gets a list of user attributes from the table in the default SSO login page."""
    def __init__(self):
        super().__init__()
        self.login_status: Literal["success", "failure"] = "failure"
        self.attributes: Optional[dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        # Check for the "alert-sucess" class on a div
        if tag == "div":
            for name, value in attrs:
                if name == "class" and value == "alert alert-success":
                    self.login_status = "success"
                    break

    def feed(self, data):
        super().feed(data)
        if self.login_status == "success":
            assert self.tables[0], "Login successfull, but attribute table not found."
            self.attributes = {}
            for row in self.tables[0][1:]:
                assert len(row) == 2, "Abnormal row length found in attribute table."
                assert isinstance(
                    row[0], str
                ), "Abnormal row name found in attribute table."
                attr_name = row[0].strip()
                value_seq = row[1].lstrip("[").rstrip("]").split(", ")

                # Regularize some typical attributes
                if attr_name == "displayName":
                    self.attributes["full_name"] = value_seq[0]
                elif attr_name == "givenName":
                    self.attributes["given_name"] = value_seq[0]
                elif attr_name == "sn":
                    self.attributes["first_last_name"] = value_seq[0]
                elif attr_name == "apellidomaterno":
                    self.attributes["second_last_name"] = value_seq[0]
                elif attr_name == "apellidos":
                    self.attributes["surnames"] = value_seq[0]
                elif attr_name == "uid":
                    self.attributes["username"] = value_seq[0]
                elif attr_name == "mailAlternateAddress":
                    self.attributes["alternate_emails"] = value_seq
                elif attr_name == "businessCategory":
                    self.attributes["user_category"] = value_seq[0]
                elif attr_name == "employeeType":
                    self.attributes["user_type"] = value_seq[0]
                elif attr_name == "tipocorreo":
                    self.attributes["email_type"] = value_seq[0]
                elif attr_name == "carlicense":
                    self.attributes["run"] = value_seq[0].lstrip("0")
                elif attr_name == "UDCIdentifier":
                    self.attributes["udc_id"] = value_seq[0]
                elif attr_name in (
                    "eduPersonScopedAffiliation",
                    "cn",
                    "organizationName",
                ):
                    continue
                else:
                    # Fallback for unknown attributes
                    # For attributes with empty values
                    if len(value_seq) == 1 and value_seq[0].strip() == "":
                        continue
                    # For one value attributes
                    elif len(value_seq) == 1:
                        self.attributes[attr_name] = value_seq[0]
                    # For multiple value attributes
                    elif len(value_seq) > 1:
                        self.attributes[attr_name] = value_seq


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
        raise ValueError(f"Could not login to SSO. Status code: {response.status_code}")

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
        raise ValueError(
            f"Could not reach service. Status code: {initial_service_response.status_code}"
        )
    if not initial_service_response.is_redirect:
        raise ValueError("Service doesn't seem to be SSO protected.")

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
        raise ValueError(
            f"Could get ticket from SSO. Status code: {login_response.status_code}"
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
