rule TTP_XOR_WriteProcessMemory_8051 {
  strings:
    $key_8051 = { d7 23 [2] e5 01 [2] e3 34 [2] cd 34 [2] f2 28 }

  condition:
    any of them
}