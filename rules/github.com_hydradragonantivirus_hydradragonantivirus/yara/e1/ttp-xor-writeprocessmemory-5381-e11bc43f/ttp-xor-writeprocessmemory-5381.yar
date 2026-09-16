rule TTP_XOR_WriteProcessMemory_5381 {
  strings:
    $key_5381 = { 04 f3 [2] 36 d1 [2] 30 e4 [2] 1e e4 [2] 21 f8 }

  condition:
    any of them
}