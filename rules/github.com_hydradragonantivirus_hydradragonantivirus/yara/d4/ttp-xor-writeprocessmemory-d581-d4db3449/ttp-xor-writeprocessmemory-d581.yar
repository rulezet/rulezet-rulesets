rule TTP_XOR_WriteProcessMemory_d581 {
  strings:
    $key_d581 = { 82 f3 [2] b0 d1 [2] b6 e4 [2] 98 e4 [2] a7 f8 }

  condition:
    any of them
}