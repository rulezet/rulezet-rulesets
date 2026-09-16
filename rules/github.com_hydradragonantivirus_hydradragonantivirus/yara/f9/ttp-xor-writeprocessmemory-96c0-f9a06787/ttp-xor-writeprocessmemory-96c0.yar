rule TTP_XOR_WriteProcessMemory_96c0 {
  strings:
    $key_96c0 = { c1 b2 [2] f3 90 [2] f5 a5 [2] db a5 [2] e4 b9 }

  condition:
    any of them
}