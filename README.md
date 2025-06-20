# awslogin

A basic replacement for `aws sso login` for those who don't have the AWS CLI installed.

Expects `$HOME/.aws/config` in the following format:

```
[default]
region = us-east-1
sso_account_id = 1234567890
sso_session = my-sso
sso_role_name = MyRole

[sso-session my-sso]
sso_region = us-east-1
sso_start_url = https://MYORG.awsapps.com/start
sso_registration_scopes = sso:account:access
```

See [AWS documentation](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html) for more details.
