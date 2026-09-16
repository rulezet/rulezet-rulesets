rule TTP_XOR_WriteProcessMemory_83c0 {
  strings:
    $key_83c0 = { d4 b2 [2] e6 90 [2] e0 a5 [2] ce a5 [2] f1 b9 }

  condition:
    any of them
}