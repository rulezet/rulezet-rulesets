rule TTP_XOR_WriteProcessMemory_d5a1 {
  strings:
    $key_d5a1 = { 82 d3 [2] b0 f1 [2] b6 c4 [2] 98 c4 [2] a7 d8 }

  condition:
    any of them
}