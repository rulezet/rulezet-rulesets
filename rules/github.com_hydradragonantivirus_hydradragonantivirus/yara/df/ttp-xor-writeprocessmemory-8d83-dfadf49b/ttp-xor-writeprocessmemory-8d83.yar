rule TTP_XOR_WriteProcessMemory_8d83 {
  strings:
    $key_8d83 = { da f1 [2] e8 d3 [2] ee e6 [2] c0 e6 [2] ff fa }

  condition:
    any of them
}