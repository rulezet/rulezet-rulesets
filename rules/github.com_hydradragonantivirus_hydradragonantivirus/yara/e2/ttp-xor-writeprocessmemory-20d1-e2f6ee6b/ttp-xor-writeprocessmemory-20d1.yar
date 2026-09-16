rule TTP_XOR_WriteProcessMemory_20d1 {
  strings:
    $key_20d1 = { 77 a3 [2] 45 81 [2] 43 b4 [2] 6d b4 [2] 52 a8 }

  condition:
    any of them
}