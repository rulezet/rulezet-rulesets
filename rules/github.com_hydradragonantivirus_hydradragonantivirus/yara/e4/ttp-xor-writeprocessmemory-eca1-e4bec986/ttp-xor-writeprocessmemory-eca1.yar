rule TTP_XOR_WriteProcessMemory_eca1 {
  strings:
    $key_eca1 = { bb d3 [2] 89 f1 [2] 8f c4 [2] a1 c4 [2] 9e d8 }

  condition:
    any of them
}