rule TTP_XOR_WriteProcessMemory_49c3 {
  strings:
    $key_49c3 = { 1e b1 [2] 2c 93 [2] 2a a6 [2] 04 a6 [2] 3b ba }

  condition:
    any of them
}