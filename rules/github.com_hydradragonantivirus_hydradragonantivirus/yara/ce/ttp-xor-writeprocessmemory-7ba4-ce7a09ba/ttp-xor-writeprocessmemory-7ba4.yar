rule TTP_XOR_WriteProcessMemory_7ba4 {
  strings:
    $key_7ba4 = { 2c d6 [2] 1e f4 [2] 18 c1 [2] 36 c1 [2] 09 dd }

  condition:
    any of them
}