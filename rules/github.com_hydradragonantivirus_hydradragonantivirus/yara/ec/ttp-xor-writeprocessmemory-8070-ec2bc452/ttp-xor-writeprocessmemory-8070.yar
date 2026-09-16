rule TTP_XOR_WriteProcessMemory_8070 {
  strings:
    $key_8070 = { d7 02 [2] e5 20 [2] e3 15 [2] cd 15 [2] f2 09 }

  condition:
    any of them
}