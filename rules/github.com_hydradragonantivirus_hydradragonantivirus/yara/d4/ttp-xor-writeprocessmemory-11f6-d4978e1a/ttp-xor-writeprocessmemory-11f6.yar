rule TTP_XOR_WriteProcessMemory_11f6 {
  strings:
    $key_11f6 = { 46 84 [2] 74 a6 [2] 72 93 [2] 5c 93 [2] 63 8f }

  condition:
    any of them
}