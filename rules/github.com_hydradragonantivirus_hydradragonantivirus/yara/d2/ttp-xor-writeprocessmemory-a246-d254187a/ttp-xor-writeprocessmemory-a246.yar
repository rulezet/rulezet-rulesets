rule TTP_XOR_WriteProcessMemory_a246 {
  strings:
    $key_a246 = { f5 34 [2] c7 16 [2] c1 23 [2] ef 23 [2] d0 3f }

  condition:
    any of them
}