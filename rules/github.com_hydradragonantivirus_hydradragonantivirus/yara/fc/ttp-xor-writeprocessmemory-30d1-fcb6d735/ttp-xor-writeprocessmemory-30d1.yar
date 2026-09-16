rule TTP_XOR_WriteProcessMemory_30d1 {
  strings:
    $key_30d1 = { 67 a3 [2] 55 81 [2] 53 b4 [2] 7d b4 [2] 42 a8 }

  condition:
    any of them
}