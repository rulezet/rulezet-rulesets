rule TTP_XOR_WriteProcessMemory_8566 {
  strings:
    $key_8566 = { d2 14 [2] e0 36 [2] e6 03 [2] c8 03 [2] f7 1f }

  condition:
    any of them
}