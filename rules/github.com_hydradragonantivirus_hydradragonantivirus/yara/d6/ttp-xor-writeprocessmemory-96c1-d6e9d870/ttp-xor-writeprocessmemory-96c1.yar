rule TTP_XOR_WriteProcessMemory_96c1 {
  strings:
    $key_96c1 = { c1 b3 [2] f3 91 [2] f5 a4 [2] db a4 [2] e4 b8 }

  condition:
    any of them
}