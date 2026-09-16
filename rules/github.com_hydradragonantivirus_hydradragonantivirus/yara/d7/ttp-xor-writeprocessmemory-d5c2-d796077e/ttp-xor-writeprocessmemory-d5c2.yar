rule TTP_XOR_WriteProcessMemory_d5c2 {
  strings:
    $key_d5c2 = { 82 b0 [2] b0 92 [2] b6 a7 [2] 98 a7 [2] a7 bb }

  condition:
    any of them
}