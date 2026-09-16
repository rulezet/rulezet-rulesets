rule TTP_XOR_WriteProcessMemory_d8a0 {
  strings:
    $key_d8a0 = { 8f d2 [2] bd f0 [2] bb c5 [2] 95 c5 [2] aa d9 }

  condition:
    any of them
}