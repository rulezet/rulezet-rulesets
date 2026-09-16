rule TTP_XOR_WriteProcessMemory_13a1 {
  strings:
    $key_13a1 = { 44 d3 [2] 76 f1 [2] 70 c4 [2] 5e c4 [2] 61 d8 }

  condition:
    any of them
}