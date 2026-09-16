rule TTP_XOR_WriteProcessMemory_0987 {
  strings:
    $key_0987 = { 5e f5 [2] 6c d7 [2] 6a e2 [2] 44 e2 [2] 7b fe }

  condition:
    any of them
}