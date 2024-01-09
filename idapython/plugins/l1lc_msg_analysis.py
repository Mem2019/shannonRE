import ida_hexrays
import ida_funcs
import idautils
import idc

def get_func_mba(func_addr, maturity):
	func = ida_funcs.get_func(func_addr) # Convert address to func_t.
	mbr = ida_hexrays.mba_ranges_t(func) # Get mba_ranges_t from function.
	hf = ida_hexrays.hexrays_failure_t() # Error message holder.
	ida_hexrays.mark_cfunc_dirty(func.start_ea) # Delete the decompilation cache.
	mba = ida_hexrays.gen_microcode(mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity)
	if not mba:
		print("Cannot get microcode: 0x%08X (%s)" % (hf.errea, hf.desc()))
		return None
	return mba # mba_t

class ArgsFinder(ida_hexrays.minsn_visitor_t):
	def __init__(self, call_ea, arg_idxes):
		super().__init__()
		self.call_ea = call_ea
		self.arg_idxes = arg_idxes
		self.result = None

	def visit_minsn(self):
		insn = self.curins

		# Find the argument for the target call instruction only.
		if insn.ea != self.call_ea:
			return 0
		if insn.opcode != ida_hexrays.m_call and \
			insn.opcode != ida_hexrays.m_icall:
			return 0

		self.result = []
		args = insn.d.f.args

		for arg_idx in self.arg_idxes:
			# Get and check the arguments
			if arg_idx >= args.size():
				print("Warning: argument index {} out-of-bound for {}" \
					.format(arg_idx, args.size()))
				self.result.append(None)
				continue

			# Get the argument of type mop_t, and obtain the result if it is const.
			arg = args.at(arg_idx)

			# Immediate number: we get the number value.
			if arg.t == ida_hexrays.mop_n:
				self.result.append(arg.nnn.value)
			# Address of a global variable: we get the linear address.
			elif arg.t == ida_hexrays.mop_a and arg.a.t == ida_hexrays.mop_v:
				self.result.append(arg.a.g)
			else:
				self.result.append(None)

		return 0

def get_arg_val(call_ea, arg_idxes):
	visitor = ArgsFinder(call_ea, arg_idxes)
	get_func_mba(call_ea, ida_hexrays.MMAT_LVARS).for_all_insns(visitor)
	return visitor.result

def get_all_mmcif_send():
	send_from_MMC_IF = idc.get_name_ea_simple("j_send_from_MMC_IF")
	for call in idautils.CodeRefsTo(send_from_MMC_IF, False):
		# This captures all branch instructions in ARM.
		if idc.print_insn_mnem(call)[0] != 'B':
			continue

		r = get_arg_val(call, [0, 2])
		if r is None:
			continue
		print(hex(call), ':', "None" if r[0] is None else hex(r[0]), ',', \
			ida_bytes.get_strlit_contents(r[1], -1, idc.STRTYPE_C).decode())

"""
None : [MMC_IF ==> GL1] MMC_GL1_RSSI_MEASUREMENT_REQ
0xc3 : [MMC_IF ==> GL1] MMC_GL1_FCH_ACQUISITION_REQ
0xc3 : [MMC_IF ==> GL1] MMC_GL1_SCH_ACQUISITION_REQ
0x98 : [MMC_IF ==> GL1] MMC_GL1_LTE_TIMING_LATCH_CNF
None : [MMC_IF ==> GL1] MMC_GL1_LTE_CELL_SEARCH_CNF
None : [MMC_IF ==> GL1] MMC_GL1_LTE_CELL_MEASURE_CNF 
None : [MMC_IF ==> GL1] MMC_GL1_LTE_CELL_SEARCHMEASURE_CNF
None : [MMC_IF ==> NS] MMCIF_NS_TIME_AIDING_RSP
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_SUSPEND_CNF
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_RESUME_CNF
None : [MMC_IF ==> MMC_LTE] MMC_LTE_RESEL_REQ
None : [MMCIF_GMC] SEND MMC_LTE_HO_TO_LTE_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_LTE_TO_2G3G_RESEL_RSP
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CSG_VISITED_LIST_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CSG_INFO_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CSG_LIST_RSP
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CSG_SEARCH_FAIL_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_ABORT_CSG_LIST_RSP
None : [MMC_IF ==> MMC_LTE] MMC_LTE_ABORT_CSG_SEARCH_CNF
None : [MMC_IF ==> MMC_LTE] HEDGE_MM_SRVCC_INFO_UPD_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_DEDICATED_PRIOR_INFO
None : [MMC_IF ==> MMC_LTE] MMC_LTE_REG_INFO_UPD_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_SM_INFO_UPD_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CONGESTION_CONTROL_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_SM_TIMER_CONTROL_IND
None : [MMC_IF ==> MMC_LTE] HEDGE_MMC_T3245_STATUS_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_UE_CAPA_FROM_IRAT_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_PLMN_UPDATE_INFO_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_CGI_INFO_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_PLMN_SEARCH_FAIL_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_PLMN_LIST_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_PLMN_SELECT_REQ
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_UPDATE_PLMN_LIST_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_PERFORM_PLMN_ACTIONS_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_LTE_RPLMN_EARFCN_SCAN_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_BACK_GND_PLMN_LIST_FAIL_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_ABORT_BACK_GND_PLMN_LIST_CNF
None : [MMC_IF ==> MMC_LTE] MMC_LTE_INIT_CNF
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_DSDS_MODE_UPD_CNF
None : [MMC_IF ==> MMC_LTE] MMC_LTE_REDIRECT_REQ
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_REDIRECT_RSP
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_MOB_CMD_TO_IRAT_RSP
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_PERIODIC_CSG_SRCH_REQ
None : [MMC_IF ==> MMC_LTE] MMC_LTE_UE_CAPA_TO_IRAT_CNF
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_ACTIVE_RAT_IND
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_CGI_HOLD_IND
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_CGI_STOP_CNF
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_READY_IND 
0xbc : [MMC_IF ==> MMC_LTE] MMC_LTE_MM_CLEAR_TEMP_BLOCKED_PLMN_LIST_IND
None : [MMC_IF ==> MMC_LTE] MMC_LTE_MCC_CNF
None : [MMC_IF ==> MM] MMC_MM_PREPARE_CGI_REQ 
None : [MMC_IF ==> MM] MMC_MM_BPLMN_SRCH_START_IND
0x20 : [MMC_IF ==> MM] MMC_MM_BPLMN_SRCH_HOLD_IND
None : [MMC_IF ==> MM] PLMN_MM_SEARCH_REQ
None : [MMC_IF ==> MM] PLMN_MM_LIST_REQ
None : [MMC_IF ==> MM] PLMN_MM_LTE_RPLMN_EARFCN_SCAN_RSP
None : [MMC_IF ==> MM] PLMN_MM_OPLMN_LIST_INFO_IND
None : [MMC_IF ==> MM] MMC_MM_DEDICATED_PRIOR_INFO_IND
None : [MMC_IF ==> MM] MMC2G3G_MM_REG_INFO_UPD_IND
None : [MMC_IF ==> SM] MMC_SM_SM_INFO_UPD_IND
None : [MMC_IF ==> MM] PLMN_MM_UPDATE_PLMNINFO_IND
None : [MMC_IF ==> MM] PLMN_MM_UPDATE_ACTING_HPLMN_IND
None : [MMC_IF ==> MM] MMC_MM_CONGESTION_CONTROL_IND
None : [MMC_IF ==> SM] MMC_SM_SM_TIMER_CONTROL_IND
None : [MMC_IF ==> MM] MMC_MM_T3245_FORBIDDANCE_CONTROL_IND
0x20 : [MMC_IF ==> MM] MMC_MM_RESUME_REQ
0x20 : [MMC_IF ==> MM] MMC_MM_SUSPEND_REQ
None : [MMC_IF ==> MM] MMC_MM_LTE_TO_2G3G_RESEL_REQ
None : [MMC_IF ==> MM] MMC_MM_LTE_TO_2G3G_REDIRECT_REQ
None : [MMC_IF ==> MM] MMC_MM_MOB_CMD_TO_IRAT_REQ
0x20 : [MMC_IF ==> MM] MMC_MM_2G3G_TO_LTE_RESEL_RSP
0x20 : [MMC_IF ==> MM] MMC_MM_2G3G_TO_LTE_REDIRECT_RSP
None : [MMC_IF ==> MM] PLMN_MM_CSG_LIST_UPDATE_REQ
None : [MMC_IF ==> MM] PLMN_MM_CSG_LIST_REQ
None : [MMC_IF ==> MM] PLMN_MM_CSG_SEL_REQ
None : [MMC_IF ==> MM] MMC_MM_INIT_REQ 
None : [MMC_IF ==> MM] MMC_MM_CGI_ACQUISITION_REQ 
0x20 : [MMC_IF ==> MM] MMC_MM_CGI_START_REQ 
0x20 : [MMC_IF ==> MM] MMC_MM_CGI_STOP_REQ
0x20 : [MMC_IF ==> MM] MMC_MM_BPLMN_UPD_CAUSEINFO_IND
0x20 : [MMC_IF ==> MM] MMC_MM_BPLMN_SRCH_STOP_IND
0x20 : [MMC_IF ==> MM] MMC_MM_START_DRX_INFOSHARE_IND
0x20 : [MMC_IF ==> MM] PLMN_MM_ABORT_BACKGND_PLMN_LIST_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_RAT_CHANGE_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_LIST_ABORT_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_SIGNAL_PENDING_IND
0x20 : [MMC_IF ==> MM] PLMN_MM_PERFORM_PLMN_ACTIONS_RSP
0x20 : [MMC_IF ==> MM] PLMN_MM_SELECTION_COM_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_SELECT_RSP
0x20 : [MMC_IF ==> MM] MMC_MM_MCC_REQ 
None : [MMC_IF ==> MM] MMC_MM_LTE_TO_2G3G_UE_CAPA_REQ
None : [MMC_IF ==> MM] MMC_MM_2G3G_TO_LTE_UE_CAPA_CNF
0x20 : [MMC_IF ==> MM] MMC_MM_CSFB_SIG_STATUS_IND 
0x20 : [MMC_IF ==> MM] MMC_MM_T3247_FORBIDDANCE_CONTROL_IND
0x20 : [MMC_IF ==> MM] MMC_MM_SUSPEND_REQ
0x20 : [MMC_IF ==> MM] MMC_MM_HO_TO_LTE_CNF
0x20 : [MMC_IF ==> MM] PLMN_MM_ABORT_CSG_LIST_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_ABORT_CSG_SEARCH_REQ
0x20 : [MMC_IF ==> MM] PLMN_MM_PERIODIC_CSG_SEARCH_CNF
None : [MMC_IF ==> MM] PLMN_MM_CSG_VISITED_LIST_IND
0x20 : [MMC_IF ==> MM] MMC_MM_MODE_UPDATE_REQ
0x5f : [MMC_IF ==> LTE_L1LC] MMC_LTEL1_GSM_TIMING_LATCH_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_GSM_RSSI_MEASURE_CNF
0x5f : [MMC_IF ==> LTEL1LC] MMC_LTEL1_GSM_FCH_ACQ_CNF
0x5f : [MMC_IF ==> LTEL1LC] MMC_LTEL1_GSM_SCH_ACQ_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_CGI_ACQUISITION_CNF
0x5f : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_TIMING_LATCH_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_CELL_SEARCH_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_PARTIAL_SEARCH_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_TDD_PARTIAL_SEARCH_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_INIT_MEASURE_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_UMTS_MEASURE_CNF
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_LTE_CELL_SEARCH_REQ
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_LTE_MEASURE_REQ
None : [MMC_IF ==> LTEL1LC] MMC_LTEL1_LTE_SEARCH_MEASURE_REQ
0x5f : [MMC_IF ==> LTEL1LC] MMC_LTEL1_LTE_MEAS_STOP_REQ
0x5f : [MMC_IF ==> LTEL1LC] MMC_HEDGE_LTEL1_BPLMN_SRCH_HOLD_IND
None : [MMC_IF ==> LTEL1LC] MMC_HEDGE_LTEL1_BPLMN_SRCH_START_IND
0x5f : [MMC_IF ==> LTEL1LC] MMC_LTEL1_LTE_TIMING_LATCH_REQ
0x5f : [MMC_IF ==> LTE_L1LC] MMC_LTEL1_SENSOR_STATE_REQ
"""