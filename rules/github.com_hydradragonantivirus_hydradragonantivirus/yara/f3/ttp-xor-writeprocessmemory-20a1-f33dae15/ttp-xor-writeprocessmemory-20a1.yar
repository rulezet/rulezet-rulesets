rule TTP_XOR_WriteProcessMemory_20a1 {
  strings:
    $key_20a1 = { 77 d3 [2] 45 f1 [2] 43 c4 [2] 6d c4 [2] 52 d8 }

  condition:
    any of them
}