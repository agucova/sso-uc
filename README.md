# UC SSO Helper

A python library for easily authenticating to services protected by UC Chile's SSO system.

## Installation

The library is available on PyPi:

```shell
$ pip install uc_sso_helper
```

## Usage

The library exposes two main functions:

- `get_ticket(username, password, service_url)`: To get a service ticket and an authenticated service URL given a username and password.
- `get_user_info(username, password)`: To get SSO stored user attributes.