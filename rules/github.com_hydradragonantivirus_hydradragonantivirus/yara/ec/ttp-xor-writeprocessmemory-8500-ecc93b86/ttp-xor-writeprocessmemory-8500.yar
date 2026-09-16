rule TTP_XOR_WriteProcessMemory_8500 {
  strings:
    $key_8500 = { d2 72 [2] e0 50 [2] e6 65 [2] c8 65 [2] f7 79 }

  condition:
    any of them
}