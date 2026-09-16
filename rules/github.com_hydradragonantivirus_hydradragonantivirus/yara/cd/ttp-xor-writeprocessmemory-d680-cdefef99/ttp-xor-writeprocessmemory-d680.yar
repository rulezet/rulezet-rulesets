rule TTP_XOR_WriteProcessMemory_d680 {
  strings:
    $key_d680 = { 81 f2 [2] b3 d0 [2] b5 e5 [2] 9b e5 [2] a4 f9 }

  condition:
    any of them
}