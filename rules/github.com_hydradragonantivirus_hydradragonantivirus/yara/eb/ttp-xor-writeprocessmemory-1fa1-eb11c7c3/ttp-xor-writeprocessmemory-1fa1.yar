rule TTP_XOR_WriteProcessMemory_1fa1 {
  strings:
    $key_1fa1 = { 48 d3 [2] 7a f1 [2] 7c c4 [2] 52 c4 [2] 6d d8 }

  condition:
    any of them
}