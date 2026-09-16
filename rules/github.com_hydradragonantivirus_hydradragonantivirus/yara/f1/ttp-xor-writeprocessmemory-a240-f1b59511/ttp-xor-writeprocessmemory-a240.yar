rule TTP_XOR_WriteProcessMemory_a240 {
  strings:
    $key_a240 = { f5 32 [2] c7 10 [2] c1 25 [2] ef 25 [2] d0 39 }

  condition:
    any of them
}