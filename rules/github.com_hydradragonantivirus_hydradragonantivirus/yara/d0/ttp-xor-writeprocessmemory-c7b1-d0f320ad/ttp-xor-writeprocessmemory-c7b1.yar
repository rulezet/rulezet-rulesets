rule TTP_XOR_WriteProcessMemory_c7b1 {
  strings:
    $key_c7b1 = { 90 c3 [2] a2 e1 [2] a4 d4 [2] 8a d4 [2] b5 c8 }

  condition:
    any of them
}