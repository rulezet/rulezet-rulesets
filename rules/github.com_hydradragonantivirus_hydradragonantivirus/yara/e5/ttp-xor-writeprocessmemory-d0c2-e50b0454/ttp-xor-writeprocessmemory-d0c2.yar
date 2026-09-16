rule TTP_XOR_WriteProcessMemory_d0c2 {
  strings:
    $key_d0c2 = { 87 b0 [2] b5 92 [2] b3 a7 [2] 9d a7 [2] a2 bb }

  condition:
    any of them
}