rule TTP_XOR_WriteProcessMemory_8546 {
  strings:
    $key_8546 = { d2 34 [2] e0 16 [2] e6 23 [2] c8 23 [2] f7 3f }

  condition:
    any of them
}