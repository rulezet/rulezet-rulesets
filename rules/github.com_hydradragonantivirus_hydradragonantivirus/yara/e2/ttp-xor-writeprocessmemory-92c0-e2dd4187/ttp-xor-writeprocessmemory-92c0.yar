rule TTP_XOR_WriteProcessMemory_92c0 {
  strings:
    $key_92c0 = { c5 b2 [2] f7 90 [2] f1 a5 [2] df a5 [2] e0 b9 }

  condition:
    any of them
}