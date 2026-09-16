rule TTP_XOR_WriteProcessMemory_fed6 {
  strings:
    $key_fed6 = { a9 a4 [2] 9b 86 [2] 9d b3 [2] b3 b3 [2] 8c af }

  condition:
    any of them
}