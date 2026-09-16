rule TTP_XOR_WriteProcessMemory_d6c4 {
  strings:
    $key_d6c4 = { 81 b6 [2] b3 94 [2] b5 a1 [2] 9b a1 [2] a4 bd }

  condition:
    any of them
}