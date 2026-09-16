rule TTP_XOR_WriteProcessMemory_85c5 {
  strings:
    $key_85c5 = { d2 b7 [2] e0 95 [2] e6 a0 [2] c8 a0 [2] f7 bc }

  condition:
    any of them
}