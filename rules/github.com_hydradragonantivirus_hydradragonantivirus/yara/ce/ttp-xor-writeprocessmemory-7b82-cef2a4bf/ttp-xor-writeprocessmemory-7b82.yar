rule TTP_XOR_WriteProcessMemory_7b82 {
  strings:
    $key_7b82 = { 2c f0 [2] 1e d2 [2] 18 e7 [2] 36 e7 [2] 09 fb }

  condition:
    any of them
}