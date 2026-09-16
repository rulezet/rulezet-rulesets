rule TTP_XOR_WriteProcessMemory_85a0 {
  strings:
    $key_85a0 = { d2 d2 [2] e0 f0 [2] e6 c5 [2] c8 c5 [2] f7 d9 }

  condition:
    any of them
}