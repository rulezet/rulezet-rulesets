rule TTP_XOR_WriteProcessMemory_79b4 {
  strings:
    $key_79b4 = { 2e c6 [2] 1c e4 [2] 1a d1 [2] 34 d1 [2] 0b cd }

  condition:
    any of them
}