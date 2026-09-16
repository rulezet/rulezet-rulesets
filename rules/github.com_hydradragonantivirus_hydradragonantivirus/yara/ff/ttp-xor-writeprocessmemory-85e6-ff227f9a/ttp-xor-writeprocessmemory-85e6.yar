rule TTP_XOR_WriteProcessMemory_85e6 {
  strings:
    $key_85e6 = { d2 94 [2] e0 b6 [2] e6 83 [2] c8 83 [2] f7 9f }

  condition:
    any of them
}