rule TTP_XOR_WriteProcessMemory_95f0 {
  strings:
    $key_95f0 = { c2 82 [2] f0 a0 [2] f6 95 [2] d8 95 [2] e7 89 }

  condition:
    any of them
}