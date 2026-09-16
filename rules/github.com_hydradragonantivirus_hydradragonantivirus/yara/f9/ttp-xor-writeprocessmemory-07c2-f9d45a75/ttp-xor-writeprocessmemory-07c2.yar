rule TTP_XOR_WriteProcessMemory_07c2 {
  strings:
    $key_07c2 = { 50 b0 [2] 62 92 [2] 64 a7 [2] 4a a7 [2] 75 bb }

  condition:
    any of them
}