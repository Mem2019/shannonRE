import ida_hexrays
import ida_funcs
import idautils
import idc
import re

c_ident = re.compile("^[a-zA-Z_][a-zA-Z0-9_]*")

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

class arg_finder(ida_hexrays.minsn_visitor_t):
	def __init__(self, call_ea, arg_idx):
		super().__init__()
		self.call_ea = call_ea
		self.arg_idx = arg_idx
		self.result = None

	def visit_minsn(self):
		insn = self.curins

		# Find the argument for the target call instruction only.
		if insn.ea != self.call_ea:
			return 0
		if insn.opcode != ida_hexrays.m_call and \
			insn.opcode != ida_hexrays.m_icall:
			return 0

		# Get and check the arguments
		args = insn.d.f.args
		if self.arg_idx >= args.size():
			print("Warning: argument index {} out-of-bound for {}" \
				.format(self.arg_idx, args.size()))
			return 0

		# Get the argument of type mop_t, and obtain the result if it is const.
		arg = args.at(self.arg_idx)

		# Immediate number: we get the number value.
		if arg.t == ida_hexrays.mop_n:
			self.result = arg.nnn.value
		# Address of a global variable: we get the linear address.
		elif arg.t == ida_hexrays.mop_a and arg.a.t == ida_hexrays.mop_v:
			self.result = arg.a.g
		else:
			print("Non-constant argument at 0x{:x} of type {}" \
				.format(insn.ea, arg.t))

		return 0

def get_arg_val(call_ea, arg_idx):
	visitor = arg_finder(call_ea, arg_idx)
	get_func_mba(call_ea, ida_hexrays.MMAT_LVARS).for_all_insns(visitor)
	return visitor.result

def label_all():

	# Refer to label_functions.py for more details.
	arg_funcs = {

		idc.get_name_ea_simple('dbg_trace_args_something_wrapper') : 1,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_0') : 1,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_1') : 0,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_2') : 0,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_4') : 1,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_5') : 0,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_6') : 0,
		idc.get_name_ea_simple('dbg_trace_args_something_wrapper_7') : 0,
		idc.get_name_ea_simple('change_Stack_ID') : 1

	}

	for target_f_ea, arg_n in arg_funcs.items():
		if target_f_ea == idc.BADADDR:
			continue

		# Find all code reference to the function.
		for ref in idautils.CodeRefsTo(target_f_ea, True):

			# Skip references not in function.
			func_ea = idc.get_func_attr(ref, idc.FUNCATTR_START)
			if func_ea == idc.BADADDR:
				continue

			# This captures all branch instructions in ARM.
			if idc.print_insn_mnem(ref)[0] != 'B':
				continue

			# Try to get the argument value if it is constant.
			val = get_arg_val(ref, arg_n)
			if val is None:
				continue
			name = ida_bytes.get_strlit_contents(val, -1, idc.STRTYPE_C).decode()

			# Find the first C ident as the caller function name.
			res = re.match(c_ident, name)
			if res is not None:
				name = res.group()
				print("Setting 0x%x to name %s" % (func_ea, name))
				idc.set_name(func_ea, name)