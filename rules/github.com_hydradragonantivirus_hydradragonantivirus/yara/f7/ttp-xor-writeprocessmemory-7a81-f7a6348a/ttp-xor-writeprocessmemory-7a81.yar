rule TTP_XOR_WriteProcessMemory_7a81 {
  strings:
    $key_7a81 = { 2d f3 [2] 1f d1 [2] 19 e4 [2] 37 e4 [2] 08 f8 }

  condition:
    any of them
}