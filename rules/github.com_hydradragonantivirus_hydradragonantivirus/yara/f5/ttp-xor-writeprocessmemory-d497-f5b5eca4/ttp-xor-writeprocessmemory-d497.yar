rule TTP_XOR_WriteProcessMemory_d497 {
  strings:
    $key_d497 = { 83 e5 [2] b1 c7 [2] b7 f2 [2] 99 f2 [2] a6 ee }

  condition:
    any of them
}