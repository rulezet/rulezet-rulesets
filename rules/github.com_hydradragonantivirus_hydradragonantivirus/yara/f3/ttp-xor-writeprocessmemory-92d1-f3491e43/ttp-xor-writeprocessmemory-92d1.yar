rule TTP_XOR_WriteProcessMemory_92d1 {
  strings:
    $key_92d1 = { c5 a3 [2] f7 81 [2] f1 b4 [2] df b4 [2] e0 a8 }

  condition:
    any of them
}