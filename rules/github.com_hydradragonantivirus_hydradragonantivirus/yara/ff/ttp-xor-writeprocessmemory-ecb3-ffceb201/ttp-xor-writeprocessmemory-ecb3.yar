rule TTP_XOR_WriteProcessMemory_ecb3 {
  strings:
    $key_ecb3 = { bb c1 [2] 89 e3 [2] 8f d6 [2] a1 d6 [2] 9e ca }

  condition:
    any of them
}