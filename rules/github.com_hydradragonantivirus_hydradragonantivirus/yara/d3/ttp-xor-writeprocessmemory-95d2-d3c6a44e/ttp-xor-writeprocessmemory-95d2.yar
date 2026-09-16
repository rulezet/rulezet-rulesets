rule TTP_XOR_WriteProcessMemory_95d2 {
  strings:
    $key_95d2 = { c2 a0 [2] f0 82 [2] f6 b7 [2] d8 b7 [2] e7 ab }

  condition:
    any of them
}