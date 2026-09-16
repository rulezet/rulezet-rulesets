rule TTP_XOR_WriteProcessMemory_15f6 {
  strings:
    $key_15f6 = { 42 84 [2] 70 a6 [2] 76 93 [2] 58 93 [2] 67 8f }

  condition:
    any of them
}