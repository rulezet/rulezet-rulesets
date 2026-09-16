rule TTP_XOR_WriteProcessMemory_8560 {
  strings:
    $key_8560 = { d2 12 [2] e0 30 [2] e6 05 [2] c8 05 [2] f7 19 }

  condition:
    any of them
}