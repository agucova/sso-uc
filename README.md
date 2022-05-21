# UC SSO Helper 🔐

A python library for easily authenticating to services protected by UC Chile's SSO system.

Note this is meant for accessing services locally (i.e. not on a web app or on a user-facing system). This is commonly used for automating software that runs local-first, and you should **almost never** use this library by capturing user credentials and storing them in your system.

For web apps you can either request to be placed on the CAS allowlist (which requires DI authorization) or in the case you need simple email or name metadata, use Google OAuth and check for a valid university domain.


## Installation

The library is available on PyPi:

```shell
$ pip install uc-sso
```

## Usage

The library exposes two main functions:

- `get_ticket(username, password, service_url)`: To get a service ticket and an authenticated service URL given a username and password.
- `get_user_info(username, password)`: To get SSO stored user attributes.

The library is heavily typed and the [code](https://github.com/agucova/sso-uc/blob/main/uc_sso/main.py) is relatively short and heavily documented, so go look!

### Seguimiento Curricular

A minimal example to place an authenticated GET request to UC Chile's "Seguimiento Curricular" service:


```python
import requests

from uc_sso import get_ticket

# This gets us the ticket value and a ready made authenticated URL to access the service.
ticket = get_ticket("example_username", "example_password", "https://seguimientocurricular.uc.cl/")

# We can now just make a GET request to the service using the autenticated URL.
requests.get(ticket.service_url).text
```

### Getting user info
A common application of this library is obtaining user metadata stored in the CAS diagnostics page. The `get_user_info` function is a simple wrapper around the page that automatically handles authentication, parsing, and cleaning the resulting attributes.

```python
from uc_sso import get_user_info

# We just need to provide the user credentials and voilà!
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
 "alternate_emails": ["XXXXXX@puc.cl"],
 "user_category": "Alumno",
 "user_type": "1"
}
```

# Contributing

I'm trying to keep this library as simple and dependency-free as possible, but if you have any ideas or suggestions, please [let me know](https://agucova.dev)!
