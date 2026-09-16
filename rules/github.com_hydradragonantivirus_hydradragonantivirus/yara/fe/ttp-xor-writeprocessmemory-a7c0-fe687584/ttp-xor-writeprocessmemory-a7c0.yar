rule TTP_XOR_WriteProcessMemory_a7c0 {
  strings:
    $key_a7c0 = { f0 b2 [2] c2 90 [2] c4 a5 [2] ea a5 [2] d5 b9 }

  condition:
    any of them
}