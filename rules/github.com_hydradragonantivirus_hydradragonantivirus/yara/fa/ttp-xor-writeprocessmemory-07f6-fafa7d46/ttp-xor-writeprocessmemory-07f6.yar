rule TTP_XOR_WriteProcessMemory_07f6 {
  strings:
    $key_07f6 = { 50 84 [2] 62 a6 [2] 64 93 [2] 4a 93 [2] 75 8f }

  condition:
    any of them
}