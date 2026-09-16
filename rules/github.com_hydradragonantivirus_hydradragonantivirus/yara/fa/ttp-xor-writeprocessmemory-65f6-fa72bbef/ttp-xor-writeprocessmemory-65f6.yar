rule TTP_XOR_WriteProcessMemory_65f6 {
  strings:
    $key_65f6 = { 32 84 [2] 00 a6 [2] 06 93 [2] 28 93 [2] 17 8f }

  condition:
    any of them
}