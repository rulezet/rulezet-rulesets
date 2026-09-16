rule TTP_XOR_WriteProcessMemory_81d2 {
  strings:
    $key_81d2 = { d6 a0 [2] e4 82 [2] e2 b7 [2] cc b7 [2] f3 ab }

  condition:
    any of them
}