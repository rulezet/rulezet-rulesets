rule TTP_XOR_WriteProcessMemory_5081 {
  strings:
    $key_5081 = { 07 f3 [2] 35 d1 [2] 33 e4 [2] 1d e4 [2] 22 f8 }

  condition:
    any of them
}