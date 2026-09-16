rule TTP_XOR_WriteProcessMemory_c096 {
  strings:
    $key_c096 = { 97 e4 [2] a5 c6 [2] a3 f3 [2] 8d f3 [2] b2 ef }

  condition:
    any of them
}