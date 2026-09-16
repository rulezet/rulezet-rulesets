rule TTP_XOR_WriteProcessMemory_d0a1 {
  strings:
    $key_d0a1 = { 87 d3 [2] b5 f1 [2] b3 c4 [2] 9d c4 [2] a2 d8 }

  condition:
    any of them
}