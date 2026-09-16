rule TTP_XOR_WriteProcessMemory_fed5 {
  strings:
    $key_fed5 = { a9 a7 [2] 9b 85 [2] 9d b0 [2] b3 b0 [2] 8c ac }

  condition:
    any of them
}