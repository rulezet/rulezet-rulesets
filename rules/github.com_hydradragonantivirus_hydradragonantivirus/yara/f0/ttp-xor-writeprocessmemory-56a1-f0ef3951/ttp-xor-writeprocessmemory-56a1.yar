rule TTP_XOR_WriteProcessMemory_56a1 {
  strings:
    $key_56a1 = { 01 d3 [2] 33 f1 [2] 35 c4 [2] 1b c4 [2] 24 d8 }

  condition:
    any of them
}