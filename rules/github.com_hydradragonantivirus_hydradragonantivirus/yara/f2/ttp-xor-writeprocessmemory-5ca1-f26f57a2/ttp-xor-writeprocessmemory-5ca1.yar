rule TTP_XOR_WriteProcessMemory_5ca1 {
  strings:
    $key_5ca1 = { 0b d3 [2] 39 f1 [2] 3f c4 [2] 11 c4 [2] 2e d8 }

  condition:
    any of them
}