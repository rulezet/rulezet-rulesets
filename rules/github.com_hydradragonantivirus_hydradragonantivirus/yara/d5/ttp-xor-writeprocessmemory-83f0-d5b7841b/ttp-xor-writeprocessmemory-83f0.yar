rule TTP_XOR_WriteProcessMemory_83f0 {
  strings:
    $key_83f0 = { d4 82 [2] e6 a0 [2] e0 95 [2] ce 95 [2] f1 89 }

  condition:
    any of them
}