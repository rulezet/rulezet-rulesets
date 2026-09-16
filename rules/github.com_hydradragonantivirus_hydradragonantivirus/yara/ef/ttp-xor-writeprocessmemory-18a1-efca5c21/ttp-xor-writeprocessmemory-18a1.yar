rule TTP_XOR_WriteProcessMemory_18a1 {
  strings:
    $key_18a1 = { 4f d3 [2] 7d f1 [2] 7b c4 [2] 55 c4 [2] 6a d8 }

  condition:
    any of them
}