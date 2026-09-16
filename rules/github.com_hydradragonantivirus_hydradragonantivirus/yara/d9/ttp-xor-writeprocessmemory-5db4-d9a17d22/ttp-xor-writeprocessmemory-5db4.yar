rule TTP_XOR_WriteProcessMemory_5db4 {
  strings:
    $key_5db4 = { 0a c6 [2] 38 e4 [2] 3e d1 [2] 10 d1 [2] 2f cd }

  condition:
    any of them
}