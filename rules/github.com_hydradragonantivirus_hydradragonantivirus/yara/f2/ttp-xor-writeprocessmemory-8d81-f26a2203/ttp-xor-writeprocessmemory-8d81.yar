rule TTP_XOR_WriteProcessMemory_8d81 {
  strings:
    $key_8d81 = { da f3 [2] e8 d1 [2] ee e4 [2] c0 e4 [2] ff f8 }

  condition:
    any of them
}