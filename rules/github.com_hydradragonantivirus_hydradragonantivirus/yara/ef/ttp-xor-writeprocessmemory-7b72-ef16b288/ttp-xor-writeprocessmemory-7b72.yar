rule TTP_XOR_WriteProcessMemory_7b72 {
  strings:
    $key_7b72 = { 2c 00 [2] 1e 22 [2] 18 17 [2] 36 17 [2] 09 0b }

  condition:
    any of them
}