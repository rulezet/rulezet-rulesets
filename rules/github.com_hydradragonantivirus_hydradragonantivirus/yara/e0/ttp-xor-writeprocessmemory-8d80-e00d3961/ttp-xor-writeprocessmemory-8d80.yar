rule TTP_XOR_WriteProcessMemory_8d80 {
  strings:
    $key_8d80 = { da f2 [2] e8 d0 [2] ee e5 [2] c0 e5 [2] ff f9 }

  condition:
    any of them
}