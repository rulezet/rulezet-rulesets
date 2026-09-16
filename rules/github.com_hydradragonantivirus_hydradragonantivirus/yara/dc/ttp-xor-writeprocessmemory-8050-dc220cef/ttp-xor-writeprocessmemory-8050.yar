rule TTP_XOR_WriteProcessMemory_8050 {
  strings:
    $key_8050 = { d7 22 [2] e5 00 [2] e3 35 [2] cd 35 [2] f2 29 }

  condition:
    any of them
}