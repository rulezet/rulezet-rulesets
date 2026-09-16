rule TTP_XOR_WriteProcessMemory_a2f7 {
  strings:
    $key_a2f7 = { f5 85 [2] c7 a7 [2] c1 92 [2] ef 92 [2] d0 8e }

  condition:
    any of them
}