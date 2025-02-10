import logging
import socket
from enum import Enum
from typing import Literal, Optional

from helpers.waiter import try_wait
from media.media import Audio as AudioMedia, Video as VideoMedia
from SIP.sip_factory import SIPMessage, SIPStatus, SIPMessageType
from SIP.sip_manager import SipFlow
from _implement_call import _Call, _CallAudioWrapper, _CallVideoWrapper


logger = logging.getLogger(__name__)


class PhoneStatus(Enum):
    INACTIVE = "INACTIVE"
    REGISTERING = "REGISTERING"
    REGISTERED = "REGISTERED"
    DEREGISTER = "DEREGISTER"
    FAILED = "FAILED"


class Phone:
    stt_workers_num = 1

    def __init__(
        self,
        call_type: Literal['Audio'] | Literal['Video'],
        stand: str,
        pbx_host: str,
        pbx_port: int,
        username: str,
        password: str,
        dial_prefix: str = ''
    ):
        self.call_type = call_type
        self.stand = stand
        self.pbx_host = pbx_host
        self.pbx_port = pbx_port
        self.username = username
        self.password = password
        self.dial_prefix = dial_prefix
        self._status: Optional[PhoneStatus] = None

        self.calls: dict[str, _Call] = dict()  # Не гарантируется что звонки в списке живые/остановленные
        self._sip = SipFlow(
            self.pbx_host,
            self.pbx_port,
            username,
            password,
            self._get_socket(connected=True),
            self._callback,
        )
        self._call_wrapper = _CallAudioWrapper if self.call_type == 'Audio' else _CallVideoWrapper
        self._media_manager = AudioMedia if self.call_type == 'Audio' else VideoMedia
        self._media_manager.init_stt_workers(self.stt_workers_num)

    def __del__(self):
        self.stop()

    def _del_call(self, call_id: str) -> None:
        self.calls.pop(call_id)

    def _callback(self, request: SIPMessage) -> None:
        requested_call = try_wait(
            lambda: self.calls[request.headers['Call-ID']],
            wait_time=2,
            raise_after_time=True,
            message_on_error=f'Не смогли получить инстанс звонка для Call-ID {request.headers["Call-ID"]}'
        )
        if request.type == SIPMessageType.MESSAGE:
            if request.method == "BYE":
                requested_call._handle_bye(request)
            else:
                raise RuntimeError(f'Unknown SIP message: {request.method}')
        else:
            if request.status == SIPStatus.TRYING:
                requested_call._handle_trying(request)
            elif request.status == SIPStatus.OK:
                requested_call._handle_OK(request)
            elif request.status == SIPStatus.NOT_FOUND:
                requested_call._handle_not_found(request)
            elif request.status == SIPStatus.SERVICE_UNAVAILABLE:
                requested_call._handle_unavailable(request)
            elif request.status == SIPStatus.UNAUTHORIZED:
                requested_call._handle_unauthorized(request)
            elif request.status == SIPStatus.PROXY_AUTHENTICATION_REQUIRED:
                print('handle 407')
                requested_call._handle_unauthorized(request)
            else:
                raise RuntimeError(f'Unknown sip status: {request.status}')

    def _get_socket(self, connected: bool = False) -> socket.socket:
        """Get available socket.
        :return: tuple[port, socket instance]
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        if connected:
            sock.connect((self.pbx_host, int(self.pbx_port)))
        return sock

    @property
    def status(self) -> PhoneStatus:
        return self._status

    def start(self) -> "Phone":
        logger.info('Проходим регистрацию на АТС')
        self._status = PhoneStatus.REGISTERING
        self._sip.start()
        self._status = PhoneStatus.REGISTERED
        return self

    def hangup(self, call: _Call) -> None:
        self._stop_call(call.call_data['call_id'])

    def call(self, number: Optional[str] = '') -> _CallAudioWrapper | _CallVideoWrapper:
        logger.info(f'Начинаем новый звонок. Номер набора: {number}')
        new_call = self._call_wrapper(
            stand=self.stand,
            pbx_info={'host': self.pbx_host, 'port': self.pbx_port},
            sip_manager=self._sip,
            media_manager=self._media_manager(self._get_socket()),
        )
        new_call._new_call(f'{self.dial_prefix}{number}')
        self.calls[new_call.call_data['call_id']] = new_call
        return new_call

    def stop(self) -> None:
        logger.info('Завершаем работу телефона')
        if self.calls:
            # time.sleep(1)  # быстрый фикс проблемы одновременного завершения звонка
            # через инстанс звонка и через инстанса телефона
            # на который я уже забил болт и забыл.
            # пока вроде не стреляет, если опять попадется, то буду знать откуда начинать копать.
            for call_id in list(self.calls.keys()):
                self._stop_call(call_id)
        self._status = PhoneStatus.DEREGISTER
        self._sip.stop()
        self._status = PhoneStatus.INACTIVE

    def _stop_call(self, call_id):
        logger.info(f'Завершаем звонок {call_id}')
        if call := self.calls.get(call_id):
            call._hangup()
            self._del_call(call_id)
