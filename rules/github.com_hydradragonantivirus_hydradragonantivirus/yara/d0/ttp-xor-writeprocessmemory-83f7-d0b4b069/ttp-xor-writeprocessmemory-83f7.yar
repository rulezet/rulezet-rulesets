rule TTP_XOR_WriteProcessMemory_83f7 {
  strings:
    $key_83f7 = { d4 85 [2] e6 a7 [2] e0 92 [2] ce 92 [2] f1 8e }

  condition:
    any of them
}