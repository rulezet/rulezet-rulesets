rule TTP_XOR_WriteProcessMemory_69a3 {
  strings:
    $key_69a3 = { 3e d1 [2] 0c f3 [2] 0a c6 [2] 24 c6 [2] 1b da }

  condition:
    any of them
}