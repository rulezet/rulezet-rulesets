rule TTP_XOR_WriteProcessMemory_9f0e {
  strings:
    $key_9f0e = { c8 7c [2] fa 5e [2] fc 6b [2] d2 6b [2] ed 77 }

  condition:
    any of them
}