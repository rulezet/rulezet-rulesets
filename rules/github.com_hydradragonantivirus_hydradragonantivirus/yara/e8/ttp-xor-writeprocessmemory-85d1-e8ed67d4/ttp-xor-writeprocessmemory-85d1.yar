rule TTP_XOR_WriteProcessMemory_85d1 {
  strings:
    $key_85d1 = { d2 a3 [2] e0 81 [2] e6 b4 [2] c8 b4 [2] f7 a8 }

  condition:
    any of them
}