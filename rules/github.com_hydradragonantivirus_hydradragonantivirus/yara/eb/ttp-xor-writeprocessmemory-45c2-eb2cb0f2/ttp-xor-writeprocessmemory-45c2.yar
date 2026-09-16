rule TTP_XOR_WriteProcessMemory_45c2 {
  strings:
    $key_45c2 = { 12 b0 [2] 20 92 [2] 26 a7 [2] 08 a7 [2] 37 bb }

  condition:
    any of them
}