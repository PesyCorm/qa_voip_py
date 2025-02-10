# write patterns:
#   local - текст парсится по паттернам, будет определен как приоритетный и единственный аудио фрагмент:
#       % ... % - часть по умолчанию, не распознаем, конкатим из эталона вместе с остальными паттернами
#       {d} - заменяем слово на цифру из аудио фрагмента
from enum import Enum

from qa_tools.call_logic.v3.data.ivr_messages import *


# В индексы кладем все, что может возникнуть на текущем этапе (+- 1 этап).
# В разных индексах сообщения могут частично дублировать предыдущий/следующий этап - это нормально.


class _IVR_Index:
    """base index for type hinting"""


class _MappingIndex(_IVR_Index, Enum):
    @classmethod
    def index_list_messages(cls):
        return {k: v.value for k, v in cls.__dict__['_member_map_'].items()}


class VoIPNotification(_MappingIndex):
        FOR_CALL_DISPATCHER_PRESS_DIGIT = FOR_CALL_DISPATCHER_PRESS_DIGIT


class RedialIndex(_IVR_Index):
    local = '% Введите % {d} {d}'


class EnterPinIndex(_MappingIndex):
    ENTER_PIN = ENTER_PIN
    INCORRECT_NUMBER = INCORRECT_NUMBER
    INCORRECT_PIN = INCORRECT_PIN
    CARD_IN_USE = CARD_IN_USE
    HAVENT_RECV_ANY_INFO_TRY_PIN_AGAIN = HAVENT_RECV_ANY_INFO_TRY_PIN_AGAIN

    INCORRECT_PIN__ENTER_PIN = INCORRECT_PIN__ENTER_PIN
    INCORRECT_NUMBER__ENTER_PIN = INCORRECT_NUMBER__ENTER_PIN
    HAVENT_RECV_ANY_INFO_TRY_PIN_AGAIN__ENTER_PIN = HAVENT_RECV_ANY_INFO_TRY_PIN_AGAIN__ENTER_PIN


class EnterDestIndex(_MappingIndex):  # noqa
    INCORRECT_NUMBER = INCORRECT_NUMBER
    CARD_IN_USE = CARD_IN_USE
    INCORRECT_PIN = INCORRECT_PIN
    ENTER_DEST = ENTER_DEST
    NUMBER_NOT_ALLOWED = NUMBER_NOT_ALLOWED

    NUMBER_NOT_ALLOWED__ENTER_DEST = NUMBER_NOT_ALLOWED__ENTER_DEST


class GsmToBB(_MappingIndex):
    PRESS_1_TO_BB = PRESS_1_TO_BB
    STAY_TO_GSM = STAY_TO_GSM


class CallBlockNotification(_MappingIndex):
    CARD_NOT_REGISTERED = CARD_NOT_REGISTERED
    TAXPHONE_OFF_ADMINISTR = TAXPHONE_OFF_ADMINISTR
    MN_UNAVAILABLE = MN_UNAVAILABLE
    NUMBER_NOT_ALLOWED = NUMBER_NOT_ALLOWED
    CARD_IN_USE = CARD_IN_USE
    GOOD_BYE = GOOD_BYE
    CARD_DAILY_LIMIT = CARD_DAILY_LIMIT

    CARD_IN_USE__GOOD_BYE = CARD_IN_USE__GOOD_BYE
    CARD_NOT_REGISTERED__ENTER_DEST = CARD_NOT_REGISTERED__ENTER_DEST
    TAXPHONE_OFF_ADMINISTR__ENTER_DEST = TAXPHONE_OFF_ADMINISTR__ENTER_DEST
    MN_UNAVAILABLE_ENTER__DEST = MN_UNAVAILABLE__ENTER_DEST
    NUMBER_NOT_ALLOWED__ENTER_DEST = NUMBER_NOT_ALLOWED__ENTER_DEST
    CARD_DAILY_LIMIT__GOOD_BYE = CARD_DAILY_LIMIT__GOOD_BYE


class CallNotification(_MappingIndex):
    MN_NOTIFICATION = MN_NOTIFICATION
    GOOD_BYE = GOOD_BYE


class Service100(_MappingIndex):
    YOU_HAVE_100_RUB = YOU_HAVE_100_RUB
