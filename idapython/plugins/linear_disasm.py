import ida_bytes
import ida_funcs
import idc

# Are bytes in [addr:addr+size) all undefined?
def is_undefined(addr, size):
	for p in range(addr, addr + size):
		if not ida_bytes.is_unknown(ida_bytes.get_flags(p)):
			return False
	return True

def disasm_linear(addr, end):
	while addr < end:
		# Check if the next 8 bytes are undefined;
		# if so, we create a function, and exit if the creation fails.
		if is_undefined(addr, 8):
			if ida_funcs.add_func(addr):
				print("New function created at 0x%x." % addr)
			else:
				print("Cannot create function at 0x%x." % addr)

		addr += 1


# disasm_linear(defined_function_address)