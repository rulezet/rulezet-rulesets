rule TTP_XOR_WriteProcessMemory_a75e {
  strings:
    $key_a75e = { f0 2c [2] c2 0e [2] c4 3b [2] ea 3b [2] d5 27 }

  condition:
    any of them
}