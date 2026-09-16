rule TTP_XOR_WriteProcessMemory_57f6 {
  strings:
    $key_57f6 = { 00 84 [2] 32 a6 [2] 34 93 [2] 1a 93 [2] 25 8f }

  condition:
    any of them
}