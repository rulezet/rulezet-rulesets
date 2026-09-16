rule TTP_XOR_WriteProcessMemory_b7a5 {
  strings:
    $key_b7a5 = { e0 d7 [2] d2 f5 [2] d4 c0 [2] fa c0 [2] c5 dc }

  condition:
    any of them
}