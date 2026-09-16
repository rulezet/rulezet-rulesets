rule TTP_XOR_WriteProcessMemory_85e2 {
  strings:
    $key_85e2 = { d2 90 [2] e0 b2 [2] e6 87 [2] c8 87 [2] f7 9b }

  condition:
    any of them
}