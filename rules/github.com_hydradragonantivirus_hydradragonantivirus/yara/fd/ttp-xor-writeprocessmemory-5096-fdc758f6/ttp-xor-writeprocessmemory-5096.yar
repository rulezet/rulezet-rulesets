rule TTP_XOR_WriteProcessMemory_5096 {
  strings:
    $key_5096 = { 07 e4 [2] 35 c6 [2] 33 f3 [2] 1d f3 [2] 22 ef }

  condition:
    any of them
}