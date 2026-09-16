rule TTP_XOR_WriteProcessMemory_8d82 {
  strings:
    $key_8d82 = { da f0 [2] e8 d2 [2] ee e7 [2] c0 e7 [2] ff fb }

  condition:
    any of them
}