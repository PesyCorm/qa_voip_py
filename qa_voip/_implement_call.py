import time
from enum import Enum
import logging
from threading import Lock

from qa_tools.api.voip.opensips import OpenSIPS
from qa_tools.call_logic.v3.data.ivr_indexes import *
from qa_tools.tools.wait_expected_result import try_wait
from qa_tools.call_logic.v3.SIP.sip_manager import SipFlow
from qa_tools.call_logic.v3.SIP.sip_factory import SIPMessage
from qa_tools.call_logic.v3.media.media import Audio as AudioMedia, \
    Video as VideoMedia, TransmitType, NoMatchesRecognize


logger = logging.getLogger(__name__)


class CallState(Enum):
    DIALING = "DIALING"
    RINGING = "RINGING"
    TRYING = "TRYING"
    ANSWERED = "ANSWERED"
    ENDED = "ENDED"


class CallStopReason(Enum):
    SIP_ERROR = "SIP_ERROR"
    BYE_FROM_PBX = "BYE_FROM_PBX"
    BYE_FROM_LOCAL = "BYE_FROM_LOCAL"


class _Call:
    def __init__(
        self,
        pbx_info: dict,
        sip_manager: SipFlow,
        media_manager: AudioMedia | VideoMedia
    ):
        self.locker = Lock()

        self.sip_manager = sip_manager
        self.media_manager = media_manager

        self.call_data = dict()
        self.call_data['available_payload'] = media_manager.available_codecs
        self.call_data['media_port'] = self.media_manager.data['port']
        self.call_data['type'] = self.CALL_TYPE  # noqa
        self.call_data['state'] = None
        self.call_data['sendtype'] = TransmitType.SENDRECV
        self.call_data['pbx_info'] = pbx_info

    def __log(self, msg):
        logger.info(f'{self.call_data["call_id"]}: {msg}')

    def _parse_invite(self, request: SIPMessage) -> None:
        new_data = {
            'invite_request': request,
            'call_id': request.headers['Call-ID'],
            'sess_id': request.body['o']['id']
        }
        # Этого пока что хватит, можно докинуть при необходимости
        self.call_data.update(new_data)

    def _stop_media(self):
        self.media_manager.stop()

    def _set_state(self, state: CallState) -> None:
        self.locker.acquire()
        self.call_data['state'] = state
        self.locker.release()

    def _stop(self):
        if self.call_data['state'] and self.call_data['state'] != CallState.ENDED:
            if self.call_data['stop_reason'] == CallStopReason.BYE_FROM_PBX:
                if hasattr(self, 'bye_recv_delay'):
                    time.sleep(self.bye_recv_delay)
                self._stop_media()
                self._set_state(CallState.ENDED)
            elif self.call_data['state'] in (CallState.TRYING, CallState.ANSWERED):
                self.sip_manager.send_bye(self.call_data['invite_request'])
                try_wait(
                    lambda: self.call_data['state'] == CallState.ENDED,
                    check_result_eq_true=True,
                    wait_time=5,
                    raise_after_time=True,
                    message_on_error='Не получили 200 OK (BYE) от АТС при завершении звонка'
                )
                self._stop_media()
                if self.call_data.get('stop_reason') != CallStopReason.BYE_FROM_LOCAL:
                    raise Exception(
                        'При остановке звонка по инициативе абонента А, '
                        'должна быть указана корректная причина остановки.'
                    )
            else:
                raise RuntimeError('Unknown _Call._stop() caller')

    def _check_leg_A_answered(self):  # noqa
        try_wait(
            awaitable=lambda: self.call_data['state'] == CallState.ANSWERED,
            check_result_eq_true=True,
            raise_after_time=True,
            message_on_error='Не дозвонились до АТС'
        )

    def _handle_trying(self, request: SIPMessage) -> None:
        self._set_state(CallState.TRYING)

    def _handle_unauthorized(self, request: SIPMessage) -> None:
        if not self.call_data.get('auth_sent'):
            self.sip_manager.send_ack(request)
            self.sip_manager.send_invite(
                self.call_data['number'],
                self.call_data['media_port'],
                self.call_data['sendtype'],
                self.call_data['available_payload'],
                self.call_data['sess_id'],
                request
            )
            self.call_data['auth_sent'] = True
        else:
            raise RuntimeError('Не смогли авторизовать звонок, дважды получен 401')

    def _handle_not_found(self, request: SIPMessage) -> None:
        self.call_data['stop_reason'] = CallStopReason.SIP_ERROR
        self.call_data['error'] = {'type': 'not found', 'request': request}
        self.sip_manager.send_ack(request)
        self._stop()

    def _handle_unavailable(self, request: SIPMessage) -> None:
        self.call_data['stop_reason'] = CallStopReason.SIP_ERROR
        self.call_data['error'] = {'type': 'unavailable', 'request': request}
        self.sip_manager.send_ack(request)
        self._stop()

    def _handle_OK(self, request: SIPMessage) -> None:  # noqa
        if self.call_data['state'] == CallState.TRYING:
            self._set_state(CallState.ANSWERED)
            self.media_manager._set_socket_connection(
                (self.call_data['pbx_info']['host'], request.body['m'][0]['port'])
            )
            self.sip_manager.send_ack(request)
        elif self.call_data['state'] == CallState.ANSWERED and request.headers['CSeq']['method'] == 'BYE':
            self._set_state(CallState.ENDED)
        elif self.call_data['state'] == CallState.ANSWERED and request.headers['CSeq']['method'] == 'INVITE':
            logger.warning('Повторно получили 200 OK (INVITE)')
        else:
            raise Exception('Получили 200 OK, но статус звонка не является DIALING/ANSWERED')

    def _handle_bye(self, request: SIPMessage):
        self.sip_manager.send_ok(request)
        self.call_data['stop_reason'] = CallStopReason.BYE_FROM_PBX
        self._stop()

    def _new_call(self, number: str) -> None:
        if not self.call_data.get('call_id'):
            self.call_data['number'] = number
            new_call_data = self.sip_manager.send_invite(
                number, self.call_data['media_port'], self.call_data['sendtype'], self.call_data['available_payload']
            )
            self._parse_invite(new_call_data)
        else:
            raise Exception('Для оригинации нового звонка используй инстанс *Phone')

    def _hangup(self) -> None:
        if self.call_data['state'] != CallState.ENDED:
            self.call_data['stop_reason'] = CallStopReason.BYE_FROM_LOCAL
            self._stop()

    def set_bye_recv_delay(self, delay: int = 3) -> None:
        """Установить паузу перед обработкой BYE от АТС.
        Требуется в случае, если BYE приходит раньше, чем успеваем обработать все полученные медиа пакеты.
        """
        self.bye_recv_delay = delay

    def send_audio(self, file_path: str):
        self.__log(f'Отправляем аудио в сторону АТС. Аудио файл: {file_path}')
        self._check_leg_A_answered()
        self.media_manager.send_audio(file_path)

    def send_dtmf(self, number: str):
        self.__log(f'Отправляем dtmf "{number}" в сторону АТС')
        self._check_leg_A_answered()
        self.media_manager.send_dtmf(number)

    def listen(self, ivr_message) -> dict:
        self.__log(f'Прослушиваем запись: "{ivr_message}"')
        self._check_leg_A_answered()
        return self.media_manager.listen(ivr_message)

    def in_call(self, time_in: int):
        """Ожидать время звонка
        :param time_in: время в звонке
        """
        self.__log(f'Ожидаем {time_in} сек в звонке')
        time.sleep(time_in)

    def check_pbx_drop_call(self, wait: int = 5, raise_after_time: bool = True) -> None:
        """Проверить, что АТС сбросила звонок."""
        try_wait(
            lambda: self.call_data['stop_reason'] == CallStopReason.BYE_FROM_PBX,
            check_result_eq_true=True,
            wait_time=wait,
            raise_after_time=raise_after_time,
            message_on_error='Звонок должен быть сброшен со стороны АТС'
        )


class _CallAudioWrapper(_Call):
    CALL_TYPE = 'Audio'

    def __init__(
            self,
            stand: str,
            pbx_info: dict,
            sip_manager: SipFlow,
            media_manager: AudioMedia
    ):
        self.osips = OpenSIPS(stand)
        super().__init__(pbx_info, sip_manager, media_manager)

    def __log(self, msg):
        logger.info(f'{self.call_data["call_id"]}: {msg}')

    def enter_redial(self):
        self.__log('Вводим редиал')
        try:
            rd = self.listen(RedialIndex)['local'].split()
        except NoMatchesRecognize:
            # быстрый фикс, т.к. дорабатывать логику слишком долго.
            # такое может случиться, если перед вводом редиала нам предлагается вызвать дежурного.
            rd = self.listen(RedialIndex)['local'].split()
        assert len(rd) == 3, f'Неправильно распознали редиал.\nОжидалось: "Введите * *"\nПолучили: {rd}'
        self.send_dtmf(f'{rd[1]}{rd[2]}')

    def enter_pin(self, card_pin):
        self.__log(f'Вводим пин: "{card_pin}"')
        self.listen(EnterPinIndex.ENTER_PIN)
        self.send_dtmf(card_pin)

    def enter_dst_number(self, phone_number: str, service: bool = False):
        """Ввести номер назначения.
        :param phone_number: номер назначения
        :param service: номер назначения это сервис (если да, то устанавливается пауза перед обработкой BYE от АТС)
        """
        self.__log(f'Вводим номер назначения: "{phone_number}"')
        self.listen(EnterDestIndex.ENTER_DEST)
        self.send_dtmf(phone_number)
        if service:
            self.set_bye_recv_delay()

    def wait_dial_up(
            self,
            dst_number: str,
            max_wait_time: int = 20,
            raise_after_time: bool = True
    ):
        """Дождаться дозвона до номера назначения.
        TODO на данный момент, метод подходит только для направлений идущих через opensips и имеющих уникальный номер Б.
        :param dst_number: номер назначения, на который проходит звонок (единственный доступный нам идентификатор)
        :param max_wait_time: максимальное время ожидания дозвона (в секундах)
        :param raise_after_time: выбросить исключение, если не дождались
        """
        def _check_dial_up():
            dlg_list = self.osips.dlg_list().json()
            for dlg in dlg_list['result']['Dialogs']:
                if dst_number in dlg['to_uri']:
                    if dlg['state'] in (3, 4):
                        # https://github.com/OpenSIPS/opensips/blob/3.4.4/modules/dialog/README#L2282
                        # на практике статус 4 не встречал, но это тоже является подходящим состоянием
                        return True
                    raise AssertionError(f'Информация по звонку на номер {dst_number} найдена, но state != 3 | 4')
            raise KeyError(f'Не нашли информации по звонку на номер {dst_number}')

        try_wait(
            _check_dial_up,
            frequency=0,
            check_result_eq_true=True,
            wait_time=max_wait_time,
            raise_after_time=raise_after_time
        )
