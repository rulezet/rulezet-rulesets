rule TTP_XOR_WriteProcessMemory_50d2 {
  strings:
    $key_50d2 = { 07 a0 [2] 35 82 [2] 33 b7 [2] 1d b7 [2] 22 ab }

  condition:
    any of them
}