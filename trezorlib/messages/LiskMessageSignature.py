# Automatically generated by pb2py
from .. import protobuf as p


class LiskMessageSignature(p.MessageType):
    FIELDS = {
        1: ('address', p.UnicodeType, 0),
        2: ('signature', p.BytesType, 0),
    }
    MESSAGE_WIRE_TYPE = 119
