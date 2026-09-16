rule TTP_XOR_WriteProcessMemory_96b0 {
  strings:
    $key_96b0 = { c1 c2 [2] f3 e0 [2] f5 d5 [2] db d5 [2] e4 c9 }

  condition:
    any of them
}