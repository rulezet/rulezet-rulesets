rule TTP_XOR_WriteProcessMemory_d491 {
  strings:
    $key_d491 = { 83 e3 [2] b1 c1 [2] b7 f4 [2] 99 f4 [2] a6 e8 }

  condition:
    any of them
}