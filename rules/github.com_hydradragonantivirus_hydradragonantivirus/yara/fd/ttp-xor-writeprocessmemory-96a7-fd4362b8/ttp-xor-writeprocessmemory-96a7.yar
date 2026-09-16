rule TTP_XOR_WriteProcessMemory_96a7 {
  strings:
    $key_96a7 = { c1 d5 [2] f3 f7 [2] f5 c2 [2] db c2 [2] e4 de }

  condition:
    any of them
}