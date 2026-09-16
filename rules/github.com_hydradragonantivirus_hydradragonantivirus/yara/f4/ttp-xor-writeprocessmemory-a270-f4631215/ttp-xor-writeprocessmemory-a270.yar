rule TTP_XOR_WriteProcessMemory_a270 {
  strings:
    $key_a270 = { f5 02 [2] c7 20 [2] c1 15 [2] ef 15 [2] d0 09 }

  condition:
    any of them
}