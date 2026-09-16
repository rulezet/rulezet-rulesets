rule TTP_XOR_WriteProcessMemory_7b80 {
  strings:
    $key_7b80 = { 2c f2 [2] 1e d0 [2] 18 e5 [2] 36 e5 [2] 09 f9 }

  condition:
    any of them
}