rule TTP_XOR_WriteProcessMemory_92d4 {
  strings:
    $key_92d4 = { c5 a6 [2] f7 84 [2] f1 b1 [2] df b1 [2] e0 ad }

  condition:
    any of them
}