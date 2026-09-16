rule TTP_XOR_WriteProcessMemory_20d2 {
  strings:
    $key_20d2 = { 77 a0 [2] 45 82 [2] 43 b7 [2] 6d b7 [2] 52 ab }

  condition:
    any of them
}