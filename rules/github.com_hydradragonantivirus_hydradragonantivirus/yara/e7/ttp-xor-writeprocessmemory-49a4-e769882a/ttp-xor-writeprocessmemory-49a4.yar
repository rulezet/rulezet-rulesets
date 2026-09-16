rule TTP_XOR_WriteProcessMemory_49a4 {
  strings:
    $key_49a4 = { 1e d6 [2] 2c f4 [2] 2a c1 [2] 04 c1 [2] 3b dd }

  condition:
    any of them
}