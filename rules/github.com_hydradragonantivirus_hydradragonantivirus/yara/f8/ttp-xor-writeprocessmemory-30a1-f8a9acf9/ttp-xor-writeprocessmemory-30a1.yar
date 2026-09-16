rule TTP_XOR_WriteProcessMemory_30a1 {
  strings:
    $key_30a1 = { 67 d3 [2] 55 f1 [2] 53 c4 [2] 7d c4 [2] 42 d8 }

  condition:
    any of them
}