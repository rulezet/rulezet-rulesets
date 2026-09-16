rule TTP_XOR_WriteProcessMemory_b3b0 {
  strings:
    $key_b3b0 = { e4 c2 [2] d6 e0 [2] d0 d5 [2] fe d5 [2] c1 c9 }

  condition:
    any of them
}