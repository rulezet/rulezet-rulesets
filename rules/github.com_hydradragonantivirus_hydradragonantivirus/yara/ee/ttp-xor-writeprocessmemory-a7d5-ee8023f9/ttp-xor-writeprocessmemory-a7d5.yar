rule TTP_XOR_WriteProcessMemory_a7d5 {
  strings:
    $key_a7d5 = { f0 a7 [2] c2 85 [2] c4 b0 [2] ea b0 [2] d5 ac }

  condition:
    any of them
}