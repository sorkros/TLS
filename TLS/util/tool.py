import sys,ssl,logging,string,random
from pprint import pprint as pp


__PROTO_TAG = "PROTOCOL_"
__OP_NO_TAG = "OP_NO_"
__OP_NO_TAG_LEN = len(__OP_NO_TAG)
_PROTOS_DATA = list()
for item_name in dir(ssl):
    if item_name.startswith(__OP_NO_TAG) and item_name[-1].isdigit():
        op_no_item = getattr(ssl, item_name)
        if op_no_item:
            proto_name = item_name[__OP_NO_TAG_LEN:]
            _PROTOS_DATA.append((proto_name, getattr(ssl, __PROTO_TAG + proto_name, -1), op_no_item))
del __OP_NO_TAG_LEN
del __OP_NO_TAG
del __PROTO_TAG

def print_data(ctx):
    print("Options: {:08X} ({!r})".format(ctx.options, ctx.options))
    print("Protocols:")
    for proto in get_protocols(ctx):
        print("    {:s} - {:d}".format(*proto))
    print()

def get_protocols(ctx):
    supported_classes = (ssl.SSLContext,)
    if not isinstance(ctx, supported_classes):
        raise TypeError("Argument must be an instance of `{:}`".format(supported_classes[0] if len(supported_classes) == 1 else supported_classes))
    protocols = list()
    for proto_data in _PROTOS_DATA:
        if ctx.options & proto_data[-1] != proto_data[-1]:
            protocols.append(proto_data[:-1])
    return protocols

def removing_tls(ctx, num = 0) :
    try : 
        if num == 0 :
            ctx.options |= ssl.OP_NO_TLSv1
        elif num == 1 :
            ctx.options |= ssl.OP_NO_TLSv1_1
        elif num == 2 :
            ctx.options |= ssl.OP_NO_TLSv1_2
        elif num == 3 :
            ctx.options |= ssl.OP_NO_TLSv1_3
    except Exception as e :
        logging.warning(e)

def refresh_tls(ctx) :
    try : 
        ctx.options -= ssl.OP_NO_TLSv1
        ctx.options -= ssl.OP_NO_TLSv1_1
        ctx.options -= ssl.OP_NO_TLSv1_2
        ctx.options -= ssl.OP_NO_TLSv1_3
    except Exception as e :
        logging.warning(e)
    
def log():
    print("\nComputed protocols:")
    pp([item[:-1] + (hex(item[-1]),) for item in _PROTOS_DATA])
    print()
