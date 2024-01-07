# Alertmanager-express-bridge

- Receive alerts from alertmanager on /api/v1/alert?group_chat_id=$group_chat_id endpoint
- Send formated alert to $group_chat_id express chat on EXPRESS_URL endpoint

## Links

Production http://alertmanager-express-bridge.express:8000/api/v1/alert?group_chat_id=$group_chat_id

Staging    http://alertmanager-express-bridge-staging.express:8000/api/v1/alert?group_chat_id=$group_chat_id

Review     http://alertmanager-express-bridge-review.express:8000/api/v1/alert?group_chat_id=$group_chat_id

# Envs

EXPRESS_URL - url of express notification api

EXPRESS_TOKEN_HASH - base64 hash of express bot token