rule TTP_XOR_WriteProcessMemory_a267 {
  strings:
    $key_a267 = { f5 15 [2] c7 37 [2] c1 02 [2] ef 02 [2] d0 1e }

  condition:
    any of them
}