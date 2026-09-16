rule TTP_XOR_WriteProcessMemory_3081 {
  strings:
    $key_3081 = { 67 f3 [2] 55 d1 [2] 53 e4 [2] 7d e4 [2] 42 f8 }

  condition:
    any of them
}