rule TTP_XOR_WriteProcessMemory_c284 {
  strings:
    $key_c284 = { 95 f6 [2] a7 d4 [2] a1 e1 [2] 8f e1 [2] b0 fd }

  condition:
    any of them
}