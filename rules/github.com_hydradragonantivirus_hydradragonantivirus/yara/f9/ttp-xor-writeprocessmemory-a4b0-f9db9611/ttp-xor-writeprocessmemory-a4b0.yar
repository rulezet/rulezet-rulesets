rule TTP_XOR_WriteProcessMemory_a4b0 {
  strings:
    $key_a4b0 = { f3 c2 [2] c1 e0 [2] c7 d5 [2] e9 d5 [2] d6 c9 }

  condition:
    any of them
}