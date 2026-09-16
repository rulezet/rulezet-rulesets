rule TTP_XOR_WriteProcessMemory_d5c4 {
  strings:
    $key_d5c4 = { 82 b6 [2] b0 94 [2] b6 a1 [2] 98 a1 [2] a7 bd }

  condition:
    any of them
}