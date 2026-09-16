rule TTP_XOR_WriteProcessMemory_a4a0 {
  strings:
    $key_a4a0 = { f3 d2 [2] c1 f0 [2] c7 c5 [2] e9 c5 [2] d6 d9 }

  condition:
    any of them
}