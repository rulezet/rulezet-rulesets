rule TTP_XOR_WriteProcessMemory_92c3 {
  strings:
    $key_92c3 = { c5 b1 [2] f7 93 [2] f1 a6 [2] df a6 [2] e0 ba }

  condition:
    any of them
}