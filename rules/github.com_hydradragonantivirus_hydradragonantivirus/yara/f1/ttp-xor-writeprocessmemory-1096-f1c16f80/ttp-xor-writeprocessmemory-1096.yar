rule TTP_XOR_WriteProcessMemory_1096 {
  strings:
    $key_1096 = { 47 e4 [2] 75 c6 [2] 73 f3 [2] 5d f3 [2] 62 ef }

  condition:
    any of them
}