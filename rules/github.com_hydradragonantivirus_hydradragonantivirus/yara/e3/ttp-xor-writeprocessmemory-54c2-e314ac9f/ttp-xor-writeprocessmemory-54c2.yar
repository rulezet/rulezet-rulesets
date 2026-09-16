rule TTP_XOR_WriteProcessMemory_54c2 {
  strings:
    $key_54c2 = { 03 b0 [2] 31 92 [2] 37 a7 [2] 19 a7 [2] 26 bb }

  condition:
    any of them
}