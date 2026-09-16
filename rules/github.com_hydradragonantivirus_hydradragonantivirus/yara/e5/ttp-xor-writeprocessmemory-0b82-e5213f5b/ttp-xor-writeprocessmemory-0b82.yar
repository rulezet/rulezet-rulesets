rule TTP_XOR_WriteProcessMemory_0b82 {
  strings:
    $key_0b82 = { 5c f0 [2] 6e d2 [2] 68 e7 [2] 46 e7 [2] 79 fb }

  condition:
    any of them
}