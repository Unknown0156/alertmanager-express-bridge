from os import getenv
from typing import Annotated, Dict, List, Any
from pydantic import BaseModel
from fastapi import FastAPI, Header, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.exceptions import HTTPException
from passlib.context import CryptContext
import aiohttp
import logging
from elasticapm.contrib.starlette import make_apm_client, ElasticAPM

#json модель одного алерта
class AlertModel(BaseModel):
    status: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    startsAt: str
    endsAt: str
    generatorURL: str
    fingerprint: str

#json модель оповещения от алертменеджера
class AlertsModel(BaseModel):
    receiver: str
    status: str
    alerts: List[AlertModel]
    groupLabels: Dict[str, str]
    commonLabels: Dict[str, str]
    commonAnnotations: Dict[str, str]
    externalURL: str
    version: str
    groupKey: str | None = None
    truncatedAlerts: int | None = None

#фильтрация логов unicorn
class EndpointFilter(logging.Filter):
    def __init__(
        self,
        path: str,
        *args: Any,
        **kwargs: Any,
    ):
        super().__init__(*args, **kwargs)
        self._path = path

    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage().find(self._path) == -1
    
#конфигурация elasticapm агента
apm = make_apm_client({
    'SERVER_URL': 'http://elk.example.ru:8200',
    'SERVICE_NAME': 'alertmanager-express-bridge',
    'TRANSACTIONS_IGNORE_PATTERNS': ['^GET /health'],
    'DEBUG': True,
})

#фильтруем access логи
uvicorn_logger = logging.getLogger("uvicorn.access")
uvicorn_logger.addFilter(EndpointFilter(path="/health"))

#хэшер для проверки токена
pwd_hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#фастапи приложение
express_alert = FastAPI()

#elasticapm агент
express_alert.add_middleware(ElasticAPM, client=apm)

#отправка оповещения на апи экспресса
async def send_alert(content_type, token, group_chat_id, message):
    async with aiohttp.ClientSession() as session:
        url = getenv('EXPRESS_URL')
        headers = {'content-type': content_type, "Authorization": "Bearer " + token}
        json = {
                 "group_chat_id": group_chat_id,
                 "notification":
                 {
                   "status": 'ok',
                   "body": message
                 }
               }
        async with session.post(url, headers=headers, json=json) as resp:
            return str(resp.status) + " " + await resp.text()

#endpoint для получения алертов из алертменеджера
@express_alert.post("/api/v1/alert", status_code=200)
async def read_alert(
    content_type: Annotated[str, Header()],
    token: Annotated[str, Depends(oauth2_scheme)],
    group_chat_id: str,
    alerts: AlertsModel,
):
    token_hash = getenv('EXPRESS_TOKEN_HASH')
    #проверка токена
    if pwd_hasher.verify(token, token_hash):
        #формирование сообщения
        message = "Alerts [" + alerts.status.upper() +  "]:\n"
        for alert in alerts.alerts:
            message += "\n" + alert.labels["alertname"] + " [" + alert.status.upper() + "]\n"
            message += "Labels:" + "\n"
            for label in alert.labels:
                message += " - " + label + " - " + alert.labels[label] + "\n"
            message += "Annotations:" + "\n"
            for annotation in alert.annotations:
                message += " - " + annotation + " - " + alert.annotations[annotation] + "\n"
            message += "Starts at " + alert.startsAt + "\n"
            message += "Source: " + alert.generatorURL + "\n"
        message += "Url: " + alerts.externalURL
        return await send_alert(content_type, token, group_chat_id, message)
    else:
        raise HTTPException(403, "Wrong token! Your hash is " + pwd_hasher.hash(token))
    
#healthcheck
@express_alert.get("/health", status_code=200)
def healthcheck():
    return {"status": "ok"}
