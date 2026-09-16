rule TTP_XOR_WriteProcessMemory_29a1 {
  strings:
    $key_29a1 = { 7e d3 [2] 4c f1 [2] 4a c4 [2] 64 c4 [2] 5b d8 }

  condition:
    any of them
}