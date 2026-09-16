rule TTP_XOR_WriteProcessMemory_bc5e {
  strings:
    $key_bc5e = { eb 2c [2] d9 0e [2] df 3b [2] f1 3b [2] ce 27 }

  condition:
    any of them
}