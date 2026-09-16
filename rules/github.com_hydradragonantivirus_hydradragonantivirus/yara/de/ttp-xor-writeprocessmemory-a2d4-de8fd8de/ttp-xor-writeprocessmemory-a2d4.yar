rule TTP_XOR_WriteProcessMemory_a2d4 {
  strings:
    $key_a2d4 = { f5 a6 [2] c7 84 [2] c1 b1 [2] ef b1 [2] d0 ad }

  condition:
    any of them
}