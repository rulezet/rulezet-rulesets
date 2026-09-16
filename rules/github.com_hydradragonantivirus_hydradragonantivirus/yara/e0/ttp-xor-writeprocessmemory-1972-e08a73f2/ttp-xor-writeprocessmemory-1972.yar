rule TTP_XOR_WriteProcessMemory_1972 {
  strings:
    $key_1972 = { 4e 00 [2] 7c 22 [2] 7a 17 [2] 54 17 [2] 6b 0b }

  condition:
    any of them
}