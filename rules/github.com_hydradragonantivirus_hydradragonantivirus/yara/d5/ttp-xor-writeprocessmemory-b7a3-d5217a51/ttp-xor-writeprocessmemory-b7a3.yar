rule TTP_XOR_WriteProcessMemory_b7a3 {
  strings:
    $key_b7a3 = { e0 d1 [2] d2 f3 [2] d4 c6 [2] fa c6 [2] c5 da }

  condition:
    any of them
}