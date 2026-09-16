rule TTP_XOR_WriteProcessMemory_17f6 {
  strings:
    $key_17f6 = { 40 84 [2] 72 a6 [2] 74 93 [2] 5a 93 [2] 65 8f }

  condition:
    any of them
}