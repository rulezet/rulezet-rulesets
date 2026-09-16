rule TTP_XOR_WriteProcessMemory_5b82 {
  strings:
    $key_5b82 = { 0c f0 [2] 3e d2 [2] 38 e7 [2] 16 e7 [2] 29 fb }

  condition:
    any of them
}