## Usage

```bash
linkedin-oauth

# Usage: linkedin-oauth <SERVICE> <JSON_PATH> [SCOPE] [PORT]

# SERVICE: `auth`, or `refresh`
# JSON_PATH: The path to the JSON file containing the credentials.
# SCOPE: Only required for `auth`
# PORT: Only required for `auth`
```

```bash
linkedin-oauth auth /path/to/client_id.json 'space sep scopes' 8088
```
