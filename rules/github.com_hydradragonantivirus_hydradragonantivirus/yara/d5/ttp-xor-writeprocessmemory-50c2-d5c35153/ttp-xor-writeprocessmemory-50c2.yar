rule TTP_XOR_WriteProcessMemory_50c2 {
  strings:
    $key_50c2 = { 07 b0 [2] 35 92 [2] 33 a7 [2] 1d a7 [2] 22 bb }

  condition:
    any of them
}