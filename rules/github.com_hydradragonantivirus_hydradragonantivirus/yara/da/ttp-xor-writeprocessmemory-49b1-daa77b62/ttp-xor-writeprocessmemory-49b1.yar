rule TTP_XOR_WriteProcessMemory_49b1 {
  strings:
    $key_49b1 = { 1e c3 [2] 2c e1 [2] 2a d4 [2] 04 d4 [2] 3b c8 }

  condition:
    any of them
}