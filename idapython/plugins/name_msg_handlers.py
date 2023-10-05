# (C) Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils

import re

tasks = ["MM", "GMM", "CC", "SMS"]

COUNT = 0

'''
<TASK>_Decode_<MsgTypeInHungarianNotation>

- get TASK (cc/mm/gmm) from beginning of get_strlit_contents
- remove up to <==
- remove <.*> and remove (,)
- split into words by _

GMM <== RLC_GMM_SAPI_ONE_TX_COMPLETE (TBF_REL_IND)
MM <== <MM TEST MODE >  MM_OPEN_UE_TEST_LOOP_MSG
MM <== <MM TEST MODE>  MM_URRC_RESET_UE_POSITIONING
GMM <== <RADIO MSG> GMM_RAU_ACCEPT
GMM <== <GMM TEST PD RADIO MSG> EGPRS_START_RADIO_BLOCK_LOOPBACK_CMD
'''

def create_name(s):
	task = s.partition("<==")[0].strip().lower()
	msg = s.partition("<==")[2]
	msg = re.sub("<.*>|[()]", "", msg).strip()
	msg = msg.replace(" ", "_")
	words = msg.split("_")

	name = ''.join([x[0].upper() + x[1:].lower() for x in words])

	name = task + "_Decode" + name

	return name

def name_handlers(ea_from, ea_to):

	global COUNT
	if ea_from == 0xffffffff or ea_to == 0xffffffff:
		return
	print("from: 0x%08x to: 0x%08x" % (ea_from, ea_to))

	addr = ea_from
	while (addr < ea_to):

		func_to_name_ea = idc.get_wide_dword(addr) & 0xFFFFFFFE
		log_msg_ptr = idc.get_wide_dword(addr + 12)
		log_msg = idc.get_strlit_contents(log_msg_ptr).decode()

		#is that a function already?
		#There were 0 cases of this for our case
		if not idaapi.get_func(func_to_name_ea):
			print("There is no function at 0x%08x!" % func_to_name_ea)
			ida_funcs.add_func(func_to_name_ea)

		if "sms_Decode" in idc.get_func_name(func_to_name_ea) or "mm_Decode" in idc.get_func_name(func_to_name_ea) or "cc_Decode" in idc.get_func_name(func_to_name_ea) or "gmm_Decode" in idc.get_func_name(func_to_name_ea):
			print("Already named appropriately, don't overwrite")

		else:
			name = create_name(log_msg)
			print("Naming %s based on %s as %s" % (idc.get_func_name(func_to_name_ea), log_msg, name))
			COUNT += 1

			# TODO: enable below naming
			ret = idc.get_name_ea_simple(name)
			count = 1
			while (ret != 0xffffffff):
				count += 1
				ret = idc.get_name_ea_simple(name + "__" + "%d" % count)
			idc.set_name(func_to_name_ea, name + ("__%d" % count)*(count > 1), SN_CHECK)

		addr += 16

if __name__ == '__main__':
	from_ea = idc.get_name_ea_simple("CC_in_msgs")
	to_ea = idc.get_name_ea_simple("CC_out_msgs")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("GMM_in_msgs_1")
	to_ea = idc.get_name_ea_simple("GMM_out_msgs_1")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("GMM_in_msgs_2")
	to_ea = idc.get_name_ea_simple("GMM_in_msg_handlers_1")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("MM_in_msgs_1")
	to_ea = idc.get_name_ea_simple("MM_in_msg_handlers_1")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("MM_in_msgs_2")
	to_ea = idc.get_name_ea_simple("MM_in_msg_handlers_2")
	name_handlers(from_ea, to_ea)


	from_ea = idc.get_name_ea_simple("sms_handlers_array_1")
	to_ea = idc.get_name_ea_simple("sms_handler_ptrs_array_1")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("sms_handlers_array_2")
	to_ea = idc.get_name_ea_simple("sms_handler_ptrs_array_2")
	name_handlers(from_ea, to_ea)

	from_ea = idc.get_name_ea_simple("sms_handlers_array_3")
	to_ea = idc.get_name_ea_simple("sms_handler_ptrs_array_3")
	name_handlers(from_ea, to_ea)

	print("%d freshly named" % COUNT)
