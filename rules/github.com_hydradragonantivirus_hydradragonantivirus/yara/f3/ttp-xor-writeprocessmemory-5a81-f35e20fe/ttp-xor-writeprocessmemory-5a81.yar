rule TTP_XOR_WriteProcessMemory_5a81 {
  strings:
    $key_5a81 = { 0d f3 [2] 3f d1 [2] 39 e4 [2] 17 e4 [2] 28 f8 }

  condition:
    any of them
}