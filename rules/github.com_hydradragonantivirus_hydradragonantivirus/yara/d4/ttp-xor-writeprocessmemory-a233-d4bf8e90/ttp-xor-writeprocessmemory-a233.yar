rule TTP_XOR_WriteProcessMemory_a233 {
  strings:
    $key_a233 = { f5 41 [2] c7 63 [2] c1 56 [2] ef 56 [2] d0 4a }

  condition:
    any of them
}