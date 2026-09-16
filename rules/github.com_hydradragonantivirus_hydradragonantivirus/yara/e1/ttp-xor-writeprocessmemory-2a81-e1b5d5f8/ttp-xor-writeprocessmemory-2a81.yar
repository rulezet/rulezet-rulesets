rule TTP_XOR_WriteProcessMemory_2a81 {
  strings:
    $key_2a81 = { 7d f3 [2] 4f d1 [2] 49 e4 [2] 67 e4 [2] 58 f8 }

  condition:
    any of them
}