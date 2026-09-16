rule TTP_XOR_WriteProcessMemory_c4a1 {
  strings:
    $key_c4a1 = { 93 d3 [2] a1 f1 [2] a7 c4 [2] 89 c4 [2] b6 d8 }

  condition:
    any of them
}