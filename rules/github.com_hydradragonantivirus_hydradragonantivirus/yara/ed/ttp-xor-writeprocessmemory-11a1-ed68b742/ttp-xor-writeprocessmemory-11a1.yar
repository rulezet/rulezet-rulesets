rule TTP_XOR_WriteProcessMemory_11a1 {
  strings:
    $key_11a1 = { 46 d3 [2] 74 f1 [2] 72 c4 [2] 5c c4 [2] 63 d8 }

  condition:
    any of them
}