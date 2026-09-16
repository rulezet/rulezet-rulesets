rule TTP_XOR_WriteProcessMemory_8572 {
  strings:
    $key_8572 = { d2 00 [2] e0 22 [2] e6 17 [2] c8 17 [2] f7 0b }

  condition:
    any of them
}