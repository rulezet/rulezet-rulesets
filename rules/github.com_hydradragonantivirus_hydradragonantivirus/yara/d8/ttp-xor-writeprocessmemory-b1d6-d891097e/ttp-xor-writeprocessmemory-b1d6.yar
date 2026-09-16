rule TTP_XOR_WriteProcessMemory_b1d6 {
  strings:
    $key_b1d6 = { e6 a4 [2] d4 86 [2] d2 b3 [2] fc b3 [2] c3 af }

  condition:
    any of them
}