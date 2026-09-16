rule TTP_XOR_WriteProcessMemory_b1a4 {
  strings:
    $key_b1a4 = { e6 d6 [2] d4 f4 [2] d2 c1 [2] fc c1 [2] c3 dd }

  condition:
    any of them
}