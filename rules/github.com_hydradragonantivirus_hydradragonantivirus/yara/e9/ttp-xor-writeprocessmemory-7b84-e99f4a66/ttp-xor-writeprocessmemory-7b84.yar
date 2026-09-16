rule TTP_XOR_WriteProcessMemory_7b84 {
  strings:
    $key_7b84 = { 2c f6 [2] 1e d4 [2] 18 e1 [2] 36 e1 [2] 09 fd }

  condition:
    any of them
}