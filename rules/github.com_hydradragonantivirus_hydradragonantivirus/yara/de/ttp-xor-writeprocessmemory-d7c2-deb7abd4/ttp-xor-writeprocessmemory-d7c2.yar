rule TTP_XOR_WriteProcessMemory_d7c2 {
  strings:
    $key_d7c2 = { 80 b0 [2] b2 92 [2] b4 a7 [2] 9a a7 [2] a5 bb }

  condition:
    any of them
}