# UPDream
UPDream is a Google App Engine web app integrated with the Jawbone UP API that allows users to record and read their dreams in a virtual journal. It also provides opt-in text and UP feed notifications to remind users to write in their journal each day when they wake up in the morning. The goal of this product is to enhance dream recall (remembering dreams) which in return would aid with lucid dreaming (becoming aware of and having full control over dreams).

A keys.py file must be added to the root directory with the following in order for the app to work.

```
app_name = "GAE app name"
client_id = "UP API client ID"
app_secret = "UP API app secret"
secret_key = "GAE secret key"
secret_passphrase = "Encryption secret passphrase"
account_sid = "Twilio account ID" 
auth_token = "Twilio authentication token"
from_num = "Twilio sender number"
```
