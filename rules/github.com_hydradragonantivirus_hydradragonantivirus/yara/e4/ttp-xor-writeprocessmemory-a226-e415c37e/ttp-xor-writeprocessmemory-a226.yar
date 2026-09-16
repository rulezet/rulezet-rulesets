rule TTP_XOR_WriteProcessMemory_a226 {
  strings:
    $key_a226 = { f5 54 [2] c7 76 [2] c1 43 [2] ef 43 [2] d0 5f }

  condition:
    any of them
}