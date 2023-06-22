# (C) Copyright 2015/2016 Comsecuris UG
import idaapi
import idc
import idautils
import ida_funcs
import math

# To install capstone, run path_of_IDA\python38\python.exe -m pip install capstone
import capstone as cs

def is_func_head(mnemonic, op_str):
    # (mnemonic == "stm" and "sp!" in op_str and "lr" in op_str) or \

    if (mnemonic == "push" or mnemonic == "push.w") and "lr" in op_str:
        for i in range(0, 4): # scrach registers are not saved
            if ("r%d" % i) in op_str:
                return False
        return True
    else:
        return False

def def_functions(s_start):

    num_added_functions, num_failures = 0, 0

    s_addr = s_start
    s_end = idc.get_segm_attr(s_start, SEGATTR_END)
    print("Segment: 0x%08x-0x%08x" % (s_start, s_end))

    # 0 for arm; 1 for thumb
    disasm = [cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM), cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB)]

    while s_addr < s_end:

        # optimization assumes that function chunks are consecutive
        # (no "function-in-function" monkey business)
        if idaapi.get_func(s_addr): # if s_addr belongs to a function, we try to skip to its end

            next_func = idc.get_next_func(s_addr)
            next_addr = math.inf
            for c in idautils.Chunks(s_addr): # iterate all chunks of the function
                # c[1] is the end of the chunk;
                # only use chunks in lookahead that do not jump over the next function
                # and that are not smaller than where we are atm.
                if c[1] > s_addr and c[1] <= next_func and c[1] < next_addr:
                    next_addr = c[1] # we get the minimum end chunk address
            assert next_addr != math.inf

            print("Skipping function 0x%08x to 0x%08x" % (s_addr, next_addr))
            s_addr = next_addr

        else:
            # select disassembler according to mode
            d = disasm[idc.get_sreg(s_addr, "T")]
            try: # try to disassemble the next instruction
                _, _, mnemonic, op_str = next(d.disasm_lite(idc.get_bytes(s_addr, 8), s_addr))
            except StopIteration: # If not cannot be disassembled, try next
                s_addr += 2
                continue

            # identify the function header
            if is_func_head(mnemonic, op_str):

                print("Found function header at 0x%08x" % s_addr)
                if ida_funcs.add_func(s_addr): # try add function, if success, we skip it
                    num_added_functions += 1
                    next_addr = math.inf
                    for c in idautils.Chunks(s_addr): # get the minimum end chunk address
                        if c[1] > s_addr and c[1] < next_addr:
                            next_addr = c[1]
                    assert next_addr != math.inf
                    s_addr = next_addr

                else: # If function creation fails, also skip by 2
                    print("Failed to create function at 0x%08x" % s_addr)
                    num_failures += 1
                    s_addr += 2

            else: # if not function header, we also skip
                s_addr += 2

    print ("finished segment with %d functions added and %d failures" \
        % (num_added_functions, num_failures))

"""
num_total_added_functions = 0
for s in idautils.Segments():
    s_start = s
    if idaapi.segtype(s_start) == idaapi.SEG_CODE:
        print ("starting segment at 0x%08x" % s_start)
        num_total_added_functions += def_functions(s)
print ("Added %d functions in total" % num_total_added_functions)
"""

