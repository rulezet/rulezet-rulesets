rule TTP_XOR_WriteProcessMemory_96a0 {
  strings:
    $key_96a0 = { c1 d2 [2] f3 f0 [2] f5 c5 [2] db c5 [2] e4 d9 }

  condition:
    any of them
}