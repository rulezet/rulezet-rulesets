rule TTP_XOR_WriteProcessMemory_b1c2 {
  strings:
    $key_b1c2 = { e6 b0 [2] d4 92 [2] d2 a7 [2] fc a7 [2] c3 bb }

  condition:
    any of them
}