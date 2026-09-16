rule TTP_XOR_WriteProcessMemory_28a1 {
  strings:
    $key_28a1 = { 7f d3 [2] 4d f1 [2] 4b c4 [2] 65 c4 [2] 5a d8 }

  condition:
    any of them
}