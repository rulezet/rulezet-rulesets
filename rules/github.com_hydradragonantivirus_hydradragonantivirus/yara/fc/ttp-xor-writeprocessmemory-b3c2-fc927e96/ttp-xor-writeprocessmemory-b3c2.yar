rule TTP_XOR_WriteProcessMemory_b3c2 {
  strings:
    $key_b3c2 = { e4 b0 [2] d6 92 [2] d0 a7 [2] fe a7 [2] c1 bb }

  condition:
    any of them
}