rule TTP_XOR_WriteProcessMemory_a213 {
  strings:
    $key_a213 = { f5 61 [2] c7 43 [2] c1 76 [2] ef 76 [2] d0 6a }

  condition:
    any of them
}