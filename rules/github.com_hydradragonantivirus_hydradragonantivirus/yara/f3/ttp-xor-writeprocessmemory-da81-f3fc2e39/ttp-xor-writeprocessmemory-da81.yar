rule TTP_XOR_WriteProcessMemory_da81 {
  strings:
    $key_da81 = { 8d f3 [2] bf d1 [2] b9 e4 [2] 97 e4 [2] a8 f8 }

  condition:
    any of them
}