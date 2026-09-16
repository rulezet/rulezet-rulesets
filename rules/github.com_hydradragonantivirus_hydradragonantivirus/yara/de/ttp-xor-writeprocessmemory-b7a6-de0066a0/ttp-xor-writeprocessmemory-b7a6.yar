rule TTP_XOR_WriteProcessMemory_b7a6 {
  strings:
    $key_b7a6 = { e0 d4 [2] d2 f6 [2] d4 c3 [2] fa c3 [2] c5 df }

  condition:
    any of them
}