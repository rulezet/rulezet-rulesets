rule TTP_XOR_WriteProcessMemory_8553 {
  strings:
    $key_8553 = { d2 21 [2] e0 03 [2] e6 36 [2] c8 36 [2] f7 2a }

  condition:
    any of them
}