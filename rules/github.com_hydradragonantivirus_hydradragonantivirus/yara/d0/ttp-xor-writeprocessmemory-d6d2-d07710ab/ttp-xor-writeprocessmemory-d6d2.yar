rule TTP_XOR_WriteProcessMemory_d6d2 {
  strings:
    $key_d6d2 = { 81 a0 [2] b3 82 [2] b5 b7 [2] 9b b7 [2] a4 ab }

  condition:
    any of them
}