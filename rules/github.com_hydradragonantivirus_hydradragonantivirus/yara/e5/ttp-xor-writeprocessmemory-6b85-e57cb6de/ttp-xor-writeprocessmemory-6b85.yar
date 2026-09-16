rule TTP_XOR_WriteProcessMemory_6b85 {
  strings:
    $key_6b85 = { 3c f7 [2] 0e d5 [2] 08 e0 [2] 26 e0 [2] 19 fc }

  condition:
    any of them
}