rule TTP_XOR_WriteProcessMemory_a7d0 {
  strings:
    $key_a7d0 = { f0 a2 [2] c2 80 [2] c4 b5 [2] ea b5 [2] d5 a9 }

  condition:
    any of them
}