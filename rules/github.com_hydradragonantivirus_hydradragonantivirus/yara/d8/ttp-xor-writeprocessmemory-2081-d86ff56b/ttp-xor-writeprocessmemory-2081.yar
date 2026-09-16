rule TTP_XOR_WriteProcessMemory_2081 {
  strings:
    $key_2081 = { 77 f3 [2] 45 d1 [2] 43 e4 [2] 6d e4 [2] 52 f8 }

  condition:
    any of them
}