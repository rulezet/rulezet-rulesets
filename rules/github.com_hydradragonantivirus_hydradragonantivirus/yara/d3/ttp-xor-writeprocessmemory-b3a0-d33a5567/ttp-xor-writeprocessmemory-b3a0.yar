rule TTP_XOR_WriteProcessMemory_b3a0 {
  strings:
    $key_b3a0 = { e4 d2 [2] d6 f0 [2] d0 c5 [2] fe c5 [2] c1 d9 }

  condition:
    any of them
}