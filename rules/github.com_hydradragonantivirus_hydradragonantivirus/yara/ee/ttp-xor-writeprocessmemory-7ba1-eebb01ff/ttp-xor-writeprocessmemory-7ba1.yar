rule TTP_XOR_WriteProcessMemory_7ba1 {
  strings:
    $key_7ba1 = { 2c d3 [2] 1e f1 [2] 18 c4 [2] 36 c4 [2] 09 d8 }

  condition:
    any of them
}