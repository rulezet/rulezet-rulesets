rule TTP_XOR_WriteProcessMemory_da84 {
  strings:
    $key_da84 = { 8d f6 [2] bf d4 [2] b9 e1 [2] 97 e1 [2] a8 fd }

  condition:
    any of them
}