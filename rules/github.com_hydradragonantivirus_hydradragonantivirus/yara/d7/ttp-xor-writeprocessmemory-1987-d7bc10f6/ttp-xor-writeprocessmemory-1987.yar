rule TTP_XOR_WriteProcessMemory_1987 {
  strings:
    $key_1987 = { 4e f5 [2] 7c d7 [2] 7a e2 [2] 54 e2 [2] 6b fe }

  condition:
    any of them
}