rule TTP_XOR_WriteProcessMemory_3ba1 {
  strings:
    $key_3ba1 = { 6c d3 [2] 5e f1 [2] 58 c4 [2] 76 c4 [2] 49 d8 }

  condition:
    any of them
}