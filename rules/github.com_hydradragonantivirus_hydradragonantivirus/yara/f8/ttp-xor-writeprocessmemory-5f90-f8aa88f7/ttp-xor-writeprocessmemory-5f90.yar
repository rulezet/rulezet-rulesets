rule TTP_XOR_WriteProcessMemory_5f90 {
  strings:
    $key_5f90 = { 08 e2 [2] 3a c0 [2] 3c f5 [2] 12 f5 [2] 2d e9 }

  condition:
    any of them
}