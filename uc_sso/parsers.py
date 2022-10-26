from html.parser import HTMLParser
from typing import Any, Literal, Optional

from html_table_parser.parser import HTMLTableParser


class SSOHandshakeParser(HTMLParser):
    """
    Parses the login form from the SSO to get one of the keys needed for the initial handshake (`execution`).
    """

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
    """
    Gets a list of user attributes from the table in the default diagnostics page of the SSO system.
    """

    def __init__(self):
        super().__init__()
        self.login_status: Literal["success", "failure"] = "failure"
        self.attributes: Optional[dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        # Check for the "alert-success" class on a div
        if tag == "div":
            for name, value in attrs:
                if name == "class" and "alert-success" in value:
                    self.login_status = "success"
                    break

    def feed(self, data):
        super().feed(data)
        print(self.tables)
        print(self.login_status)
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
                elif attr_name == "mail":
                    self.attributes["email"] = value_seq[0]
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
