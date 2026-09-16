rule TTP_XOR_WriteProcessMemory_7bd1 {
  strings:
    $key_7bd1 = { 2c a3 [2] 1e 81 [2] 18 b4 [2] 36 b4 [2] 09 a8 }

  condition:
    any of them
}