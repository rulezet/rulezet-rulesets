rule TTP_XOR_WriteProcessMemory_9f3e {
  strings:
    $key_9f3e = { c8 4c [2] fa 6e [2] fc 5b [2] d2 5b [2] ed 47 }

  condition:
    any of them
}