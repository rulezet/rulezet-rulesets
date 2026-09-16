rule TTP_XOR_WriteProcessMemory_dab0 {
  strings:
    $key_dab0 = { 8d c2 [2] bf e0 [2] b9 d5 [2] 97 d5 [2] a8 c9 }

  condition:
    any of them
}