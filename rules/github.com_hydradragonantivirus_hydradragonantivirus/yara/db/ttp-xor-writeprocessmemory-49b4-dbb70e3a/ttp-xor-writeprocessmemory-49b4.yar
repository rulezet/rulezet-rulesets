rule TTP_XOR_WriteProcessMemory_49b4 {
  strings:
    $key_49b4 = { 1e c6 [2] 2c e4 [2] 2a d1 [2] 04 d1 [2] 3b cd }

  condition:
    any of them
}