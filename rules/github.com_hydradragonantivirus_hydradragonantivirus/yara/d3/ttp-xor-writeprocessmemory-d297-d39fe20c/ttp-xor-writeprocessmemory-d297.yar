rule TTP_XOR_WriteProcessMemory_d297 {
  strings:
    $key_d297 = { 85 e5 [2] b7 c7 [2] b1 f2 [2] 9f f2 [2] a0 ee }

  condition:
    any of them
}