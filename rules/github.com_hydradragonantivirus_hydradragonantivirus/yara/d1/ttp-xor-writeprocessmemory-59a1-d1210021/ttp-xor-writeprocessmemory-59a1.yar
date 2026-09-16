rule TTP_XOR_WriteProcessMemory_59a1 {
  strings:
    $key_59a1 = { 0e d3 [2] 3c f1 [2] 3a c4 [2] 14 c4 [2] 2b d8 }

  condition:
    any of them
}