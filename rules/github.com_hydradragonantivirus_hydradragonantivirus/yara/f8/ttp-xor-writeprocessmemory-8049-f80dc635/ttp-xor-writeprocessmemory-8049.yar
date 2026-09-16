rule TTP_XOR_WriteProcessMemory_8049 {
  strings:
    $key_8049 = { d7 3b [2] e5 19 [2] e3 2c [2] cd 2c [2] f2 30 }

  condition:
    any of them
}