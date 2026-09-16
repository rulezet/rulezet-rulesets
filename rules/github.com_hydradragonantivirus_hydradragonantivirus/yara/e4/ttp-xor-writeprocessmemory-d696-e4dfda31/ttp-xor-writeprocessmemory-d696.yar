rule TTP_XOR_WriteProcessMemory_d696 {
  strings:
    $key_d696 = { 81 e4 [2] b3 c6 [2] b5 f3 [2] 9b f3 [2] a4 ef }

  condition:
    any of them
}