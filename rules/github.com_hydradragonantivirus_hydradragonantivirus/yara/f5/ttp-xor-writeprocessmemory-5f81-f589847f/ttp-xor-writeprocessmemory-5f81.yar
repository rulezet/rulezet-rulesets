rule TTP_XOR_WriteProcessMemory_5f81 {
  strings:
    $key_5f81 = { 08 f3 [2] 3a d1 [2] 3c e4 [2] 12 e4 [2] 2d f8 }

  condition:
    any of them
}