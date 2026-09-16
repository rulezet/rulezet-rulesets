rule TTP_XOR_WriteProcessMemory_ecb9 {
  strings:
    $key_ecb9 = { bb cb [2] 89 e9 [2] 8f dc [2] a1 dc [2] 9e c0 }

  condition:
    any of them
}