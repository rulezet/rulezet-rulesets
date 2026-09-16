rule TTP_XOR_WriteProcessMemory_79a4 {
  strings:
    $key_79a4 = { 2e d6 [2] 1c f4 [2] 1a c1 [2] 34 c1 [2] 0b dd }

  condition:
    any of them
}