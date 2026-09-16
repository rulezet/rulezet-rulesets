rule TTP_XOR_WriteProcessMemory_b1a5 {
  strings:
    $key_b1a5 = { e6 d7 [2] d4 f5 [2] d2 c0 [2] fc c0 [2] c3 dc }

  condition:
    any of them
}