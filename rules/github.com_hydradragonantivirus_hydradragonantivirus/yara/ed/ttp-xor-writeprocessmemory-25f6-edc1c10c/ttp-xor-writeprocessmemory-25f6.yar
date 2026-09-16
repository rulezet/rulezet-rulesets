rule TTP_XOR_WriteProcessMemory_25f6 {
  strings:
    $key_25f6 = { 72 84 [2] 40 a6 [2] 46 93 [2] 68 93 [2] 57 8f }

  condition:
    any of them
}