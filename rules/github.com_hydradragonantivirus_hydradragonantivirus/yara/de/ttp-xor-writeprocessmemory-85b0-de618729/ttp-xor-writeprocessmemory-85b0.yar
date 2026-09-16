rule TTP_XOR_WriteProcessMemory_85b0 {
  strings:
    $key_85b0 = { d2 c2 [2] e0 e0 [2] e6 d5 [2] c8 d5 [2] f7 c9 }

  condition:
    any of them
}