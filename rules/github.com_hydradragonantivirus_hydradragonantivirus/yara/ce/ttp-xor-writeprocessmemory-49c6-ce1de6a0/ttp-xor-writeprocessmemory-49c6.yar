rule TTP_XOR_WriteProcessMemory_49c6 {
  strings:
    $key_49c6 = { 1e b4 [2] 2c 96 [2] 2a a3 [2] 04 a3 [2] 3b bf }

  condition:
    any of them
}