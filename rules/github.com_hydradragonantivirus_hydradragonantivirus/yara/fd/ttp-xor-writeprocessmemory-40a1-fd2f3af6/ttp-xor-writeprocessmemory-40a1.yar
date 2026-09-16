rule TTP_XOR_WriteProcessMemory_40a1 {
  strings:
    $key_40a1 = { 17 d3 [2] 25 f1 [2] 23 c4 [2] 0d c4 [2] 32 d8 }

  condition:
    any of them
}