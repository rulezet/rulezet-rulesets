rule TTP_XOR_WriteProcessMemory_85a6 {
  strings:
    $key_85a6 = { d2 d4 [2] e0 f6 [2] e6 c3 [2] c8 c3 [2] f7 df }

  condition:
    any of them
}