rule TTP_XOR_WriteProcessMemory_5ba1 {
  strings:
    $key_5ba1 = { 0c d3 [2] 3e f1 [2] 38 c4 [2] 16 c4 [2] 29 d8 }

  condition:
    any of them
}