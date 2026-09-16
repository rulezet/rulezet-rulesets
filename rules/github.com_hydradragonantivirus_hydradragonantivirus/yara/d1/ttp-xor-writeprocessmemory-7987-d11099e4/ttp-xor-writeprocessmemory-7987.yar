rule TTP_XOR_WriteProcessMemory_7987 {
  strings:
    $key_7987 = { 2e f5 [2] 1c d7 [2] 1a e2 [2] 34 e2 [2] 0b fe }

  condition:
    any of them
}