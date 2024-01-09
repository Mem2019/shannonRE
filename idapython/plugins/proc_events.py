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
				print("Non-constant argument at 0x{:x} of type {}" \
					.format(insn.ea, arg.t))
				self.result.append(None)

		return 0

def get_arg_val(call_ea, arg_idxes):
	visitor = ArgsFinder(call_ea, arg_idxes)
	get_func_mba(call_ea, ida_hexrays.MMAT_LVARS).for_all_insns(visitor)
	return visitor.result

def rename_events():
	create_func = idc.get_name_ea_simple("pal_SmCreateEventGroup")
	for call in idautils.CodeRefsTo(create_func, False):
		# This captures all branch instructions in ARM.
		if idc.print_insn_mnem(call)[0] != 'B':
			continue

		r = get_arg_val(call, [0, 1])
		if r is None or r[0] is None or r[1] is None:
			continue

		name = ida_bytes.get_strlit_contents(r[1], -1, idc.STRTYPE_C).decode()
		idc.set_name(r[0], "p_" + name, idc.SN_NOCHECK | 0x800)

def find_set_event():
	pass