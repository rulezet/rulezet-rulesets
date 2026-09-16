rule TTP_XOR_WriteProcessMemory_d396 {
  strings:
    $key_d396 = { 84 e4 [2] b6 c6 [2] b0 f3 [2] 9e f3 [2] a1 ef }

  condition:
    any of them
}