rule TTP_XOR_WriteProcessMemory_95e1 {
  strings:
    $key_95e1 = { c2 93 [2] f0 b1 [2] f6 84 [2] d8 84 [2] e7 98 }

  condition:
    any of them
}