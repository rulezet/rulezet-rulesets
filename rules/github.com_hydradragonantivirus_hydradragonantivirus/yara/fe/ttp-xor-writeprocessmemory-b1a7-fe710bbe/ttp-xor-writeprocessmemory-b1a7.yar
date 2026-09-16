rule TTP_XOR_WriteProcessMemory_b1a7 {
  strings:
    $key_b1a7 = { e6 d5 [2] d4 f7 [2] d2 c2 [2] fc c2 [2] c3 de }

  condition:
    any of them
}