rule TTP_XOR_WriteProcessMemory_f6a1 {
  strings:
    $key_f6a1 = { a1 d3 [2] 93 f1 [2] 95 c4 [2] bb c4 [2] 84 d8 }

  condition:
    any of them
}