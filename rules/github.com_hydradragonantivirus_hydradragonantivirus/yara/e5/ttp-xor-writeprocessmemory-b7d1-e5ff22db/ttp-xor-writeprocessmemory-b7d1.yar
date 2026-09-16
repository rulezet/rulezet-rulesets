rule TTP_XOR_WriteProcessMemory_b7d1 {
  strings:
    $key_b7d1 = { e0 a3 [2] d2 81 [2] d4 b4 [2] fa b4 [2] c5 a8 }

  condition:
    any of them
}