rule TTP_XOR_WriteProcessMemory_e281 {
  strings:
    $key_e281 = { b5 f3 [2] 87 d1 [2] 81 e4 [2] af e4 [2] 90 f8 }

  condition:
    any of them
}