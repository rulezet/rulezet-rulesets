rule TTP_XOR_WriteProcessMemory_a262 {
  strings:
    $key_a262 = { f5 10 [2] c7 32 [2] c1 07 [2] ef 07 [2] d0 1b }

  condition:
    any of them
}