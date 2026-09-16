rule TTP_XOR_WriteProcessMemory_65c2 {
  strings:
    $key_65c2 = { 32 b0 [2] 00 92 [2] 06 a7 [2] 28 a7 [2] 17 bb }

  condition:
    any of them
}