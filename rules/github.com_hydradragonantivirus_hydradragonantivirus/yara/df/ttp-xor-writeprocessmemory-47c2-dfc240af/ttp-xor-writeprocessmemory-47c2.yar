rule TTP_XOR_WriteProcessMemory_47c2 {
  strings:
    $key_47c2 = { 10 b0 [2] 22 92 [2] 24 a7 [2] 0a a7 [2] 35 bb }

  condition:
    any of them
}