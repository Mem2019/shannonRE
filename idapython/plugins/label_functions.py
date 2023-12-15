# (C) Copyright 2015/2016 Comsecuris UG
# The intention of this script is to come up with function labels based on strings within the binary
# For this we use simple heuristics and back-tracing of function arguments
import os
import idautils
import idc
import idaapi
import json
import re
import ida_hexrays
import ida_typeinf

IDAStrings = []

exact_name = 0
misc_name = 0
fuzzy_path_name = 0
fuzzy_long_path_name = 0

class arg_finder(ida_hexrays.ctree_visitor_t):
	def __init__(self, call_ea, arg_idx):
		super().__init__(ida_hexrays.CV_FAST)
		self.call_ea = call_ea
		self.arg_idx = arg_idx
		self.result = None

	def visit_insn(self, i):
		return 0

	def visit_expr(self, e):
		# If the instruction address matches the expression address,
		# we consider the expression to be the candidate.
		if e.ea != self.call_ea:
			return 0

		# Check the operand, which must be call expression.
		if e.op != ida_hexrays.cot_call:
			return 0

		# The required argument index cannot be out-of-bound.
		if self.arg_idx >= e.a.size():
			print("Error: Argument index {} is out-of-bound for size {}" \
				.format(self.arg_idx, e.a.size()))
			return 1

		# Access the argument of the required index
		arg = e.a.at(self.arg_idx)

		# For cast expression, we extract the expression being casted.
		if arg.op == ida_hexrays.cot_cast:
			arg = arg.x

		# The decompiler may recognize the string argument as either
		# a global variable or a number.
		if arg.op == ida_hexrays.cot_obj:
			self.result = arg.obj_ea
		elif arg.op == ida_hexrays.cot_num:
			self.result = arg.n.value(idaapi.tinfo_t(ida_typeinf.BT_INT64))
		elif arg.op == ida_hexrays.cot_ref and arg.x.op == ida_hexrays.cot_obj:
			self.result = arg.x.obj_ea
		else:
			print("Info: At 0x{:x}, argument with op {} is not a const. ({})" \
				.format(e.ea, arg.opname, arg.operands))
		return 0

# Given a function call instruction at `ea`, find the argument at index `arg_num`.
def trace_arg_bwd(call_ea, arg_idx):
	visitor = arg_finder(call_ea, arg_idx)
	visitor.apply_to(idaapi.decompile( \
		idc.get_func_attr(call_ea, FUNCATTR_START)).body, None)
	return "" if visitor.result is None else \
		ida_bytes.get_strlit_contents(visitor.result, -1, idc.STRTYPE_C).decode()

#######################################################################################################################################


# This returns the EAs of functions that call f_ea
def find_callers(f_ea):
	callers = map(idaapi.get_func, idautils.CodeRefsTo(f_ea, 0))
	parents = []
	for ref in callers:
		if not ref:
			continue
		parents.append(ref.start_ea)

	return parents

# This returns the call site within function f_ea that calls the function target_f_ea
def find_caller(f_ea, target_f_ea):
	f = idaapi.get_func(f_ea)
	if not f:
		return None

	for caller in set(idautils.CodeRefsTo(target_f_ea, 0)):
		if f.start_ea <= caller and caller < f.end_ea:
			return caller

	return None


# this function should return the name that should be used instead
# or null if none was found
def overwrite_name_by_arg(f_ea):

	# There are several functions that give some labeling info about the caller
	# But most don't give us more than the by-reference pathname labeling already.

	# These always give extra info

	## dbg_trace_args_something_wrapper_0-6: a function name

	# This sometimes gives extra info

	## print_0: a function name - but not always

	# These give extra info if we combine the basename and the linenumber

	## fatal_error: a file basename and a linenumber
	## dbg_log_something: a file name (sometimes a basename, sometimes a path) and a linenumber
	## assert_failed: a full path (we would get that already) and a linenunber
	## sub_400B0C24: a file name (sometimes a basename, sometimes a path) and a linenumber

	# These give no extra info, we can discard them

	## sub_4084D288: a full path (we would get that already)
	## malloc, free: a full path (we would get that already)
	## rrc_system_services_something__3: a full path (we would get that already)

	# For now we only use the ones that directly give extra info in arg0 always, so the dbg_trace wrappers.
	# IMPORTANT NOTE: IDA will not know the two labels, you will have to find
	# them manually. The below list is also not complete.  For each of these
	# functions (and there is definitely more), look for the following string,
	# go to it's cross reference, and label the function for this code to work.
	# We didn't put in automation for this anymore. Sorry about that :)
	#
	# For dbg_trace_args_something_wrapper:
	#     - look for "mm_InitGmmServiceReq" string
	#     - next branch will go to dbg_trace_args_something_wrapper (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_0:
	#     - look for "ds_mm_InitGmmServiceReq" string
	#     - next branch will go to dbg_trace_args_something_wrapper_0 (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_1:
	#     - look for "mm_CoordinateAuthRej" string
	#     - next branch will go to dbg_trace_args_something_wrapper_1 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_2:
	#     - look for "mm_DecodeRrReleaseIndMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_2 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_4:
	#     - look for "sm_GetPdpAddressLength" string
	#     - next branch will go to dbg_trace_args_something_wrapper_4 (the aforementioned string is the second argument)
	# For dbg_trace_args_something_wrapper_5:
	#     - look for "sms_DecodeMmRelIndMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_5 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_6:
	#     - look for "sms_DecodeEmmCmasInfoInd" string
	#     - next branch will go to dbg_trace_args_something_wrapper_6 (the aforementioned string is the first argument)
	# For dbg_trace_args_something_wrapper_7:
	#     - look for "ds_mm_DecodeGmmSnReestReqMsg" string
	#     - next branch will go to dbg_trace_args_something_wrapper_7 (the aforementioned string is the first argument)

	# I cannot find 0 and 7, to be specific, ds_mm_* does not present in the binary.

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

		#idc.get_name_ea_simple('dbg_trace_args_something_wrapper') : 1,
		#idc.get_name_ea_simple('sub_40676D04') : 1,
		#idc.get_name_ea_simple('sub_40D20ECA') : 0,
		#idc.get_name_ea_simple('sub_40D20EAC') : 0

		#idc.get_name_ea_simple('print_0') : 0,

		#idc.get_name_ea_simple('fatal_error') : 1,
		#idc.get_name_ea_simple('assert_failed') : 1,
		#idc.get_name_ea_simple('sub_408AB208') : 1,
		#idc.get_name_ea_simple('sub_400B0C24') : 1,

		#idc.get_name_ea_simple('sub_4084D288') : 1,
		#idc.get_name_ea_simple('j_free') : 1,
		#idc.get_name_ea_simple('rrc_system_services_something__3') : 1,
	}

	for target_f_ea, arg_n in arg_funcs.items():
		if target_f_ea == 0xffffffff:
			continue
		if f_ea in find_callers(target_f_ea):
			caller_ea = find_caller(f_ea, target_f_ea)
			new_name = trace_arg_bwd(caller_ea, arg_n)

			if new_name == "":
				return None
			elif " " in new_name: #sanity check that name works as a function name
				return None
			elif ("sub_" in idc.get_func_name(f_ea)) or ("_something" in idc.get_func_name(f_ea)):
				print("Found new name: %s" % new_name)
				return new_name
			else:
				print("Found same name %s as %s" % (new_name, idc.get_func_name(f_ea)))
				return new_name

	return None

# Returns a dictionary that maps the function EA to all strings that it references.
def str_fun_xrefs():
	str_fun_xref = {}
	for s in IDAStrings:
		for ref in idautils.DataRefsTo(s.ea):
			f = idaapi.get_func(ref)
			if not f:
				continue

			if idc.print_insn_mnem(ref) == "":
				continue

			f_ea = f.start_ea
			try:
				#because we are only carrying the string value itself, duplications should be removed.
				#This is important because of OFFS/ADR instruction double references being very typical,
				#and multiple allocations/frees in same function causing extra references too.
				str_fun_xref[f_ea].add(str(s))
			except:
				str_fun_xref[f_ea] = set([str(s)])

	return str_fun_xref

# Separate the set of strings to two sets:
# 1. path strings: file paths that point to a c source file (also must contain "../")
# 2. misc strings: other strings
def path_misc_strings(str_l):
	path_strings = []
	misc_strings = []
	for s in str_l:
		if "../" in s and os.path.splitext(s)[1] == ".c":
			path_strings.append(s)
		else:
			misc_strings.append(s)

	return (path_strings, misc_strings)

# Given a path to source file, returns a module name extracted from the path.
def module_path(p):

	p_path = os.path.dirname(p)
	# the following heuristic to get rid of cruft in the path name
	# is based on the following logic:
	# strings cpcrash_dump_20150609-2313.log|grep '\.\./'|grep -vE "(code/|src/|Source/|Src|Inc)" |wc -l
	# 41
	# this shows that almost all file paths (and I didn't even only look at .c here)
	# have the common structure, which we can nicely strip away
	replace_str = ["../", "/src", "/Src", "/code", "/Code", "/Inc"]
	for rp in replace_str:
		p_path = p_path.replace(rp, "")

	# based on the strings that we see in the paths, we take the last 5 path
	# elements for the caller
	p_path = "_".join(p_path.split('/')[-5:])

	return p_path

# returns function and function caller name
def function_label(p_strings, m_strings, f_ea):
	p_str_len = len(p_strings)
	m_str_len = len(m_strings)
	p_name = None
	f_name = None
	m_name = None
	global exact_name, misc_name, fuzzy_path_name, fuzzy_long_path_name

	#Locate a possible more unique function name than what we can derive from generic or path strings
	overwrite_name = overwrite_name_by_arg(f_ea)

	if p_str_len == 1:
		exact_name += 1

		m_name = module_path(p_strings[0])

		if type(overwrite_name) == type(None):
			f_name = os.path.basename(p_strings[0])
			f_name = "%s_something" % os.path.splitext(f_name)[0]
			f_name = "%s_%s" % (m_name, f_name)

		else:
			f_name = overwrite_name

		p_name = "calls_%s" % f_name


	elif p_str_len == 2 and "../../../HEDGE/GL1/GPHY/L1X/Code/Src/l1x_srch_tch.c" in p_strings:
		#That's just an IDA messup! Ghetto way of skipping it
		if "../../../HEDGE/GL1/GPHY/L1X/Code/Src/l1x_srch_tch.c" in p_strings[0]:
			name = p_strings[1]
		else:
			name = p_strings[0]

		exact_name +=1
		m_name = module_path(name)

		if type(overwrite_name) == type(None):
			f_name = os.path.basename(name)
			f_name = "%s_something" % os.path.splitext(f_name)[0]
			f_name = "%s_%s" % (m_name, f_name)
		else:
			f_name = overwrite_name

		p_name = "calls_%s" % f_name


	elif p_str_len == 0:

		def accept_string(s):
			if len(s) < 5:
				return False
			#be alphanumberic or "_"
			elif not re.match(r'^[a-zA-Z0-9_]+$', s):
				return False
			#have consonant
			elif not re.match(r'.*[bcdfghjklmnpqrstvwxyz].*', s.lower()):
				return False
			#have vowel
			elif not re.match(r'.*[aeiou].*', s.lower()):
				return False
			return True

		if type(overwrite_name) != type(None):
			m_name = "misc"
			p_name = None
			f_name = overwrite_name
			exact_name += 1

		elif m_str_len == 1 and accept_string(m_strings[0]):

			f_name = "misc_%s_something" % m_strings[0]
			p_name = None
			m_name = "misc"
			misc_name += 1

		# if we have a small number of strings
		# and these are small, we can try to
		# use these!
		elif m_str_len > 1 and m_str_len <= 3:

			m_strings = set(filter(accept_string, set(m_strings)))
			if len(m_strings) > 0:
				f_name = "_".join(set(m_strings))
				f_name = "misc_%s_something" % f_name
				p_name = None
				m_name = "misc"

				if len(f_name) > 30:
					f_name = None
					m_name = None

				else:
					misc_name += 1


	#### These 2 cases here were all cleaned up, we no longer need them, hence everything is assigned None in them.

	# if we have less than 3 file names we
	# try a combination of these
	# for the parent we are lazy and take the part of from the first path
	elif p_str_len > 1 and p_str_len < 3:

		#These cases are all just mistakes by IDA, so this case actually does not exist in the binary at all.
		fuzzy_path_name += 1
		f_name = "_".join(set([os.path.splitext(os.path.basename(str(p)))[0] for p in p_strings]))
		f_name = "%s_something" % f_name
		f_name = "%s_%s" % (module_path(str(p_strings[0])), f_name)
		p_name = "calls_%s" % f_name

		print("Hey look, a function with two paths names at 0x%08x, would become %s" % (f_ea, f_name))
		print(p_str_len, p_strings)

		f_name = None
		p_name = None
		m_name = None

	# as a last resort we just take the first of these and name them
	# so this is visible
	elif p_str_len >= 3:

		#There is one hitting this by mistake and one that is a very unique function that we named manually. So no need for this.
		fuzzy_long_path_name += 1
		f_name = os.path.basename(str(p_strings[0]))
		f_name = "calls_%s_something" % os.path.splitext(f_name)[0]
		p_name = "calls_%s_c_%s" % (module_path(str(p_strings[0])), f_name)

		# "Hey look, a fuzzy long path name: %s at 0x%08x, would become %s" % (f_name, f_ea, f_name)
		# len(p_strings), p_strings

		f_name = None
		p_name = None
		m_name = None

	return (f_name, p_name, m_name)

def apply_labels(fun_names):
	new_sub = 0
	new_som = 0
	new_oth = 0

	named_overwrittens = []

	for f_ea, name in fun_names.items():
		name = re.sub('[^a-zA-Z0-9_]+', '', name)
		curr_name = idaapi.get_func_name(f_ea)
		if curr_name.startswith("sub_"):
			new_sub += 1
		elif "_something" in curr_name:
			new_som += 1
		else:
			new_oth += 1
			named_overwrittens.append(curr_name)
			#so we don't overwrite these
			continue

		ret = idc.get_name_ea_simple(name)
		count = 1
		while (ret != 0xffffffff):
			count += 1
			ret = idc.get_name_ea_simple(name + "__" + "%d" % count)
		idc.set_name(f_ea, name + ("__%d" % count)*(count > 1), idc.SN_CHECK)

def log_statistics(fun_name, parent_labels):

	global exact_name, misc_name, fuzzy_path_name, fuzzy_long_path_name

	print(len(fun_name))
	print("%d exact names" % exact_name)
	print("%d misc names" % misc_name)
	print("%d fuzzy path names" % fuzzy_path_name)
	print("%d fuzzy long path names" % fuzzy_long_path_name)
	print("total labeled functions: %d" %(exact_name + fuzzy_path_name + fuzzy_long_path_name + misc_name))
	print("total labeled parents: %d" % parent_labels)

def label_functions():

	global IDAStrings

	print("Collecting string references ...")

	# Get all strings that should appear in the string subview
	for s in idautils.Strings():
		IDAStrings.append(s)

	str_fun_xref = str_fun_xrefs()
	fun_name = {}
	fun_parent_name = {}
	fun_module_name = {}
	parent_labels = 0

	print("Creating labels for functions ...")

	for f_ea, str_l in str_fun_xref.items():
		(path_strings, misc_strings) = path_misc_strings(str_l)
		(f_name, p_name, m_name) = function_label(path_strings, misc_strings, f_ea)
		if f_name != None:
			fun_name[f_ea] = f_name
			fun_parent_name[f_ea] = p_name
			fun_module_name[f_ea] = m_name

	print("Assigning labels ...")

	# we apply the parents after we labeled the strings
	# and dont label the callers right away. otherwise
	# we could overwrite function names that already had an exact name
	for f_ea, name in fun_parent_name.items():
		#None for functions labels from misc strings,
		#i.e. only labeling parents of pathname-labeled functions
		if name != None:
			for p in find_callers(f_ea):
				# make sure we dont overwrite a function that already had an exact name
				# Note: a function that calls both e.g. malloc() and a module specific
				#		 function will be luck-of-the-draw which one its named after
				if p not in fun_name.keys():
					fun_name[p] = name
					parent_labels += 1
				#if not given a module name yet
				if p not in fun_module_name.keys():
					fun_module_name[p] = fun_module_name[f_ea] #parent goes into same module as called child its labeled after

	print("Applying labels to the idb ...")

	apply_labels(fun_name)

	print("Assigning module names to unlabeled functions ...")

	for f_ea in Functions():
		if f_ea not in fun_module_name.keys():
			fun_module_name[f_ea] = "unk"

		elif type(fun_module_name[f_ea]) == type(None):
			fun_module_name[f_ea] = "unk"

	print("Logging statistics ...")

	log_statistics(fun_name, parent_labels)

	print("... and done!")

label_functions()


"""
class function_labeler_plugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "foo"
	help = "bar"
	wanted_name = "function labeler"
	wanted_hotkey = "Alt-F8"

	def init(self):
		return idaapi.PLUGIN_OK

	def run(self, arg):
		label_functions()

	def term(self):
		pass


def PLUGIN_ENTRY():
	return function_labeler_plugin()
"""
