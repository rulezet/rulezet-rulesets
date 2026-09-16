rule TTP_XOR_WriteProcessMemory_d8a4 {
  strings:
    $key_d8a4 = { 8f d6 [2] bd f4 [2] bb c1 [2] 95 c1 [2] aa dd }

  condition:
    any of them
}