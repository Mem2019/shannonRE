import idc
import struct
import ida_bytes
from collections import namedtuple

MsgDesc = namedtuple('MsgDesc', \
	'msg_group size msg_id unk1 unk2 msg_flow msg_type data_type idx')

# Given a MsgDescEntry array, return information of all MsgDesc it contains.
def parse_msgdesc_entry(arr, size):
	def get_cstring(p):
		if p == 0:
			return "NULL"
		return ida_bytes.get_strlit_contents(p, -1, idc.STRTYPE_C).decode()
	ret = []
	for i in range(0, size):
		idx, desc = struct.unpack("<II", idc.get_bytes(arr + i * 8, 8))
		if desc == 0:
			continue
		data = idc.get_bytes(desc, 0x18)
		values = struct.unpack("<HHHHI", data[0:0xc])
		strings = map(get_cstring, struct.unpack("<III", data[0xc:0x18]))
		desc = MsgDesc(*values, *strings, idx)
		ret.append(desc)
	return ret

# Parse all MsgDescEntry arrays, return a dictionary mapping name to MsgDesc array.
def parse_all():
	entries = {"PssTxMsgDesc_PLMN": (0x403580c0, 0x1b), \
		"LteTxMsgDesc_PLMN": (0x40358cac, 0x19), \
		"HedgeTxMsgDesc_PLMN": (0x4035940c, 0x1A), \
		"SrncTxMsgDesc": (0x4035be34, 6), \
		"PssTxMsgDesc_MMC": (0x40356bf0, 0x18), \
		"LteTxMsgDesc_MMC": (0x4035770c, 0x25), \
		"HedgeTxMsgDesc_MMC": (0x4035c58c, 0x1b)}
	ret = dict()
	for k, (arr, size) in entries.items():
		ret[k] = parse_msgdesc_entry(arr, size)
	return ret

def find_given_msg_id(msg_id):
	for k, desc_arr in parse_all().items():
		for desc in desc_arr:
			if desc.msg_id != msg_id:
				continue
			print(("%s: idx=%s, msg_group=%s, msg_flow=\"%s\", " + \
				"msg_type=\"%s\", data_type=\"%s\"") % \
				(k, hex(desc.idx), hex(desc.msg_group), \
					desc.msg_flow, desc.msg_type, desc.data_type))
