rule TTP_XOR_WriteProcessMemory_c5c2 {
  strings:
    $key_c5c2 = { 92 b0 [2] a0 92 [2] a6 a7 [2] 88 a7 [2] b7 bb }

  condition:
    any of them
}