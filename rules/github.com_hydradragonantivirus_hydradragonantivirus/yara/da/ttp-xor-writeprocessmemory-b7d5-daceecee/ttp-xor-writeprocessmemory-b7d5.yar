rule TTP_XOR_WriteProcessMemory_b7d5 {
  strings:
    $key_b7d5 = { e0 a7 [2] d2 85 [2] d4 b0 [2] fa b0 [2] c5 ac }

  condition:
    any of them
}