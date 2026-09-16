rule TTP_XOR_WriteProcessMemory_83c1 {
  strings:
    $key_83c1 = { d4 b3 [2] e6 91 [2] e0 a4 [2] ce a4 [2] f1 b8 }

  condition:
    any of them
}