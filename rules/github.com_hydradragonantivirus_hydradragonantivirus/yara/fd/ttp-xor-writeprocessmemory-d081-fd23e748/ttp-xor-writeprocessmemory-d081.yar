rule TTP_XOR_WriteProcessMemory_d081 {
  strings:
    $key_d081 = { 87 f3 [2] b5 d1 [2] b3 e4 [2] 9d e4 [2] a2 f8 }

  condition:
    any of them
}