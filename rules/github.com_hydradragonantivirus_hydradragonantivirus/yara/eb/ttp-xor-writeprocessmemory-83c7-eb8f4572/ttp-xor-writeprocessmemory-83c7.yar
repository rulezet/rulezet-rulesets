rule TTP_XOR_WriteProcessMemory_83c7 {
  strings:
    $key_83c7 = { d4 b5 [2] e6 97 [2] e0 a2 [2] ce a2 [2] f1 be }

  condition:
    any of them
}