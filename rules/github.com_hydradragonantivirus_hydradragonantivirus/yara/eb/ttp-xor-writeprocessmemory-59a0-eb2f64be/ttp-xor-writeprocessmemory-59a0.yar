rule TTP_XOR_WriteProcessMemory_59a0 {
  strings:
    $key_59a0 = { 0e d2 [2] 3c f0 [2] 3a c5 [2] 14 c5 [2] 2b d9 }

  condition:
    any of them
}