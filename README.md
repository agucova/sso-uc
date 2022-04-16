# UC SSO Helper 🔐

A python library for easily authenticating to services protected by UC Chile's SSO system.

## Installation

The library is available on PyPi:

```shell
$ pip install uc-sso
```

## Usage

The library exposes two main functions:

- `get_ticket(username, password, service_url)`: To get a service ticket and an authenticated service URL given a username and password.
- `get_user_info(username, password)`: To get SSO stored user attributes.

The library is typed and the [code](https://github.com/agucova/sso-uc/blob/main/uc_sso_helper/main.py) is relatively short and documented.

### Portal UC

A minimal example to place an authenticated GET request to UC Chile's main portal.

```python
import requests

from uc_sso import get_ticket

ticket = get_ticket("example_username", "example_password", "https://portal.uc.cl/")
requests.get(ticket.service_url).text
```

### Getting user info

```python
from uc_sso import get_user_info
print(get_user_info("example_username", "example_password"))

>>> {
 "full_name": "AGUSTIN COVARRUBIAS XXXXXX",
 "given_name": "AGUSTÍN",
 "surnames": "COVARRUBIAS XXXXXX",
 "first_last_name": "COVARRUBIAS",
 "second_last_name": "XXXXXX",
 "mail": "XXXXXX@uc.cl",
 "email_type": "gmail",
 "username": "XXXXXXX"
 "run": "XXXXXXX-0",
 "alternate_emails": ["XXXXXX@puc.cl"]
 "user_category": "Alumno",
 "user_type": "1",
}
```