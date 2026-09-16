rule TTP_XOR_WriteProcessMemory_61a1 {
  strings:
    $key_61a1 = { 36 d3 [2] 04 f1 [2] 02 c4 [2] 2c c4 [2] 13 d8 }

  condition:
    any of them
}