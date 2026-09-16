rule TTP_XOR_WriteProcessMemory_a381 {
  strings:
    $key_a381 = { f4 f3 [2] c6 d1 [2] c0 e4 [2] ee e4 [2] d1 f8 }

  condition:
    any of them
}