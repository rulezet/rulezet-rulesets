rule TTP_XOR_WriteProcessMemory_76c2 {
  strings:
    $key_76c2 = { 21 b0 [2] 13 92 [2] 15 a7 [2] 3b a7 [2] 04 bb }

  condition:
    any of them
}