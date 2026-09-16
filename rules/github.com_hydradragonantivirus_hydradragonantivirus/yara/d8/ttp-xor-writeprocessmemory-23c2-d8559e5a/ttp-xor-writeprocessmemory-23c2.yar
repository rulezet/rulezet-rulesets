rule TTP_XOR_WriteProcessMemory_23c2 {
  strings:
    $key_23c2 = { 74 b0 [2] 46 92 [2] 40 a7 [2] 6e a7 [2] 51 bb }

  condition:
    any of them
}