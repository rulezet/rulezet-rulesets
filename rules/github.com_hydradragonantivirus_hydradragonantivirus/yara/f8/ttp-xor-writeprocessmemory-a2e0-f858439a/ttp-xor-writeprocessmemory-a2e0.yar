rule TTP_XOR_WriteProcessMemory_a2e0 {
  strings:
    $key_a2e0 = { f5 92 [2] c7 b0 [2] c1 85 [2] ef 85 [2] d0 99 }

  condition:
    any of them
}