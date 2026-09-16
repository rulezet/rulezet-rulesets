rule TTP_XOR_WriteProcessMemory_7bc1 {
  strings:
    $key_7bc1 = { 2c b3 [2] 1e 91 [2] 18 a4 [2] 36 a4 [2] 09 b8 }

  condition:
    any of them
}