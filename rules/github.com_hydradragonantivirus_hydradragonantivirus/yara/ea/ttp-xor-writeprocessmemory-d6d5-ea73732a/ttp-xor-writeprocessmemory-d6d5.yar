rule TTP_XOR_WriteProcessMemory_d6d5 {
  strings:
    $key_d6d5 = { 81 a7 [2] b3 85 [2] b5 b0 [2] 9b b0 [2] a4 ac }

  condition:
    any of them
}