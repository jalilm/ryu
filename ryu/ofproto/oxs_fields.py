import struct

from ryu.lib.pack_utils import msg_pack_into
from ryu.lib import type_desc


# enum ofp_oxs_class
OFPXSC_OPENFLOW_BASIC = 0x8002  # Basic stats class for OpenFlow
OFPXSC_EXPERIMENTER = 0xFFFF  # Experimenter class

# enum oxs_ofb_stat_fields
OFPXST_OFB_DURATION = 0  # Time flow entry has been alive.
OFPXST_OFB_IDLE_TIME = 1  # Time flow entry has been idle.
OFPXST_OFB_FLOW_COUNT = 3  # Number of aggregated flow entries.
OFPXST_OFB_PACKET_COUNT = 4  # Number of packets in flow entry.
OFPXST_OFB_BYTE_COUNT = 5  # Number of bytes in flow entry.


class _OxsClass(object):
    def __init__(self, name, num, type_):
        self.name = name
        self.oxs_type = num | (self._class << 7)
        # TODO(yamamoto): Clean this up later.
        # Probably when we drop EXT-256 style experimenter OXMs.
        self.num = self.oxs_type
        self.type = type_


class OpenFlowBasic(_OxsClass):
    _class = OFPXSC_OPENFLOW_BASIC


class Experimenter(_OxsClass):
    _class = OFPXSC_EXPERIMENTER

    def __init__(self, name, experimenter_id, num, type_):
        super(Experimenter, self).__init__(name, num, type_)
        self.experimenter_id = experimenter_id
        self.num = (self.experimenter_id, self.oxs_type)


# define OFPXST_OFB_ALL ((UINT64_C(1) << 6) - 1)

# /* Header for OXS experimenter stat fields. */
# struct ofp_oxs_experimenter_header {
# uint32_t oxs_header; /* oxs_class = OFPXSC_EXPERIMENTER */
# uint32_t experimenter; /* Experimenter ID. */
# };
# OFP_ASSERT(sizeof(struct ofp_oxs_experimenter_header) == 8);

def generate(modname):
    import sys
    import functools

    mod = sys.modules[modname]

    def add_attr(k, v):
        setattr(mod, k, v)

    for i in mod.oxs_types:
        uk = i.name.upper()
        if isinstance(i.num, tuple):
            continue
        oxs_class = i.num >> 7
        if oxs_class != OFPXSC_OPENFLOW_BASIC:
            continue
        #TODO: JALIL check the mask!
        ofpxst = i.num & 0x3f
        td = i.type
        add_attr('OFPXST_OFB_' + uk, ofpxst)
        add_attr('OXS_OF_' + uk, mod.oxs_tlv_header(ofpxst, td.size))

    name_to_field = dict((f.name, f) for f in mod.oxs_types)
    num_to_field = dict((f.num, f) for f in mod.oxs_types)
    add_attr('oxs_from_user', functools.partial(_from_user, name_to_field))
    add_attr('oxs_from_user_header',
             functools.partial(_from_user_header, name_to_field))
    add_attr('oxs_to_user', functools.partial(_to_user, num_to_field))
    add_attr('oxs_to_user_header',
             functools.partial(_to_user_header, num_to_field))
    add_attr('_oxs_field_desc', functools.partial(_field_desc, num_to_field))
    add_attr('oxs_normalize_user', functools.partial(_normalize_user, mod))
    add_attr('oxs_parse', functools.partial(_parse, mod))
    add_attr('oxs_parse_header', functools.partial(_parse_header, mod))
    add_attr('oxs_serialize', functools.partial(_serialize, mod))
    add_attr('oxs_serialize_header', functools.partial(_serialize_header, mod))
    add_attr('oxs_to_jsondict', _to_jsondict)
    add_attr('oxs_from_jsondict', _from_jsondict)


def _get_field_info_by_name(name_to_field, name):
    try:
        f = name_to_field[name]
        t = f.type
        num = f.num
    except KeyError:
        t = type_desc.UnknownType
        if name.startswith('field_'):
            num = int(name.split('_')[1])
        else:
            raise KeyError('unknown match field ' + name)
    return num, t


def _from_user_header(name_to_field, name):
    (num, t) = _get_field_info_by_name(name_to_field, name)
    return num


# def _from_user(name_to_field, name, user_value):
#     (num, t) = _get_field_info_by_name(name_to_field, name)
#     # the 'list' case below is a bit hack; json.dumps silently maps
#     # python tuples into json lists.
#     if isinstance(user_value, (tuple, list)):
#         (value, mask) = user_value
#     else:
#         value = user_value
#         mask = None
#     if value is not None:
#         value = t.from_user(value)
#     if mask is not None:
#         mask = t.from_user(mask)
#     return num, value, mask

def _from_user(name_to_field, name, user_value):
    (num, t) = _get_field_info_by_name(name_to_field, name)
    value = t.from_user(user_value)
    return num, value


def _get_field_info_by_number(num_to_field, num):
    try:
        f = num_to_field[num]
        t = f.type
        name = f.name
    except KeyError:
        t = type_desc.UnknownType
        name = 'field_%d' % (num,)
    return name, t


def _to_user_header(num_to_field, num):
    (name, t) = _get_field_info_by_number(num_to_field, num)
    return name


def _to_user(num_to_field, num, value):
    (name, t) = _get_field_info_by_number(num_to_field, num)
    if value is not None:
        if hasattr(t, 'size') and t.size != len(value):
            raise Exception(
                'Unexpected OXM payload length %d for %s (expected %d)'
                % (len(value), name, t.size))
        value = t.to_user(value)
    else:
        value = None
    return name, value


def _field_desc(num_to_field, num):
    return num_to_field[num]


def _normalize_user(mod, k, uv):
    (num, value) = mod.oxs_from_user(k, uv)
    (k2, uv2) = mod.oxm_to_user(num, value)
    assert k2 == k
    return (k2, uv2)


def _parse_header_impl(mod, buf, offset):
    hdr_pack_str = '!I'
    (header, ) = struct.unpack_from(hdr_pack_str, buf, offset)
    hdr_len = struct.calcsize(hdr_pack_str)
    oxs_type = mod.oxs_tlv_header_extract_type(header)
    oxs_class = mod.oxs_tlv_header_extract_class(header)
    oxs_length = mod.oxs_tlv_header_extract_length(header)
    if oxs_class == OFPXSC_EXPERIMENTER:
        # Experimenter OXSs have 64-bit header.  (vs 32-bit for other OXSs)
        exp_hdr_pack_str = '!I'  # experimenter_id
        (exp_id, ) = struct.unpack_from(exp_hdr_pack_str, buf,
                                        offset + hdr_len)
        exp_hdr_len = struct.calcsize(exp_hdr_pack_str)
        assert exp_hdr_len == 4
        oxs_field = oxs_type & 0x7f
        num = (exp_id, oxs_type)
    else:
        num = oxs_type
        exp_hdr_len = 0
    value_len = oxs_length - exp_hdr_len
    assert value_len > 0
    field_len = hdr_len + oxs_length
    total_hdr_len = hdr_len + exp_hdr_len
    return num, total_hdr_len, value_len, field_len


def _parse_header(mod, buf, offset):
    (oxs_type_num, total_hdr_len, value_len, field_len) = _parse_header_impl(mod, buf, offset)
    return oxs_type_num, field_len - value_len


def _parse(mod, buf, offset):
    (oxs_type_num, total_hdr_len, value_len, field_len) = _parse_header_impl(mod, buf, offset)
    # Note: OXM payload length (oxm_len) includes Experimenter ID (exp_hdr_len)
    # for experimenter OXMs.
    value_offset = offset + total_hdr_len
    value_pack_str = '!%ds' % value_len
    assert struct.calcsize(value_pack_str) == value_len
    (value, ) = struct.unpack_from(value_pack_str, buf, value_offset)
    return oxs_type_num, value, field_len


def _make_exp_hdr(mod, num):
    exp_hdr = bytearray()
    try:
        desc = mod._oxs_field_desc(num)
    except KeyError:
        return num, exp_hdr
    if isinstance(desc, Experimenter):  # XXX
        (exp_id, exp_type) = num
        assert desc.experimenter_id == exp_id
        assert desc.oxs_type == exp_type
        exp_hdr_pack_str = '!I'  # experimenter_id
        msg_pack_into(exp_hdr_pack_str, exp_hdr, 0,
                      desc.experimenter_id)
        assert len(exp_hdr) == struct.calcsize(exp_hdr_pack_str)
        num = desc.oxs_type
        assert (num >> 7) == OFPXSC_EXPERIMENTER
    return num, exp_hdr


def _serialize_header(mod, num, buf, offset):
    try:
        desc = mod._oxs_field_desc(num)
        value_len = desc.type.size
    except KeyError:
        value_len = 0
    num, exp_hdr = _make_exp_hdr(mod, num)
    exp_hdr_len = len(exp_hdr)
    pack_str = "!I%ds" % (exp_hdr_len,)
    msg_pack_into(pack_str, buf, offset,
                  (num << 9) | (0 << 8) | (exp_hdr_len + value_len),
                  bytes(exp_hdr))
    return struct.calcsize(pack_str)


def _serialize(mod, num, value, mask, buf, offset):
    num, exp_hdr = _make_exp_hdr(mod, num)
    exp_hdr_len = len(exp_hdr)
    value_len = len(value)
    pack_str = "!I%ds%ds" % (exp_hdr_len, value_len,)
    msg_pack_into(pack_str, buf, offset,
                  (num << 9) | (0 << 8) | (exp_hdr_len + value_len),
                  bytes(exp_hdr), value)
    return struct.calcsize(pack_str)


def _to_jsondict(k, uv):
    return {"OXMTlv": {"field": k, "value": uv}}


def _from_jsondict(j):
    tlv = j['OXMTlv']
    field = tlv['field']
    value = tlv['value']
    return (field, value)
