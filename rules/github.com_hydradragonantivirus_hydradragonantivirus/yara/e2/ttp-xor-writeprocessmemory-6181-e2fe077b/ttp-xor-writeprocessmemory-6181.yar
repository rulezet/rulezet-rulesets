rule TTP_XOR_WriteProcessMemory_6181 {
  strings:
    $key_6181 = { 36 f3 [2] 04 d1 [2] 02 e4 [2] 2c e4 [2] 13 f8 }

  condition:
    any of them
}