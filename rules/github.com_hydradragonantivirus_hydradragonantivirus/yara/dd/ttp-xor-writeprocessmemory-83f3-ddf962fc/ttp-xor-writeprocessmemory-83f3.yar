rule TTP_XOR_WriteProcessMemory_83f3 {
  strings:
    $key_83f3 = { d4 81 [2] e6 a3 [2] e0 96 [2] ce 96 [2] f1 8a }

  condition:
    any of them
}