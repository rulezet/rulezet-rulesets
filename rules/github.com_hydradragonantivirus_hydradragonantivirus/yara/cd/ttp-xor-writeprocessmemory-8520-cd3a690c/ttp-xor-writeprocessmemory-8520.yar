rule TTP_XOR_WriteProcessMemory_8520 {
  strings:
    $key_8520 = { d2 52 [2] e0 70 [2] e6 45 [2] c8 45 [2] f7 59 }

  condition:
    any of them
}