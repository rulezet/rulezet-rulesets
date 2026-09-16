rule TTP_XOR_WriteProcessMemory_d6d0 {
  strings:
    $key_d6d0 = { 81 a2 [2] b3 80 [2] b5 b5 [2] 9b b5 [2] a4 a9 }

  condition:
    any of them
}