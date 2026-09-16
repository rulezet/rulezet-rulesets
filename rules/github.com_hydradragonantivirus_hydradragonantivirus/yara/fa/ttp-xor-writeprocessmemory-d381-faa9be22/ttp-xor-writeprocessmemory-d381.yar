rule TTP_XOR_WriteProcessMemory_d381 {
  strings:
    $key_d381 = { 84 f3 [2] b6 d1 [2] b0 e4 [2] 9e e4 [2] a1 f8 }

  condition:
    any of them
}