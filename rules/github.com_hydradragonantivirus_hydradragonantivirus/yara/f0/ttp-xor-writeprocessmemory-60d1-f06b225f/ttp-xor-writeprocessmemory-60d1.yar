rule TTP_XOR_WriteProcessMemory_60d1 {
  strings:
    $key_60d1 = { 37 a3 [2] 05 81 [2] 03 b4 [2] 2d b4 [2] 12 a8 }

  condition:
    any of them
}