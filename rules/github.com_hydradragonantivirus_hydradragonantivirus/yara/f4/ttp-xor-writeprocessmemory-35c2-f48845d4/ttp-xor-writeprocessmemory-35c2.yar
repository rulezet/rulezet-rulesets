rule TTP_XOR_WriteProcessMemory_35c2 {
  strings:
    $key_35c2 = { 62 b0 [2] 50 92 [2] 56 a7 [2] 78 a7 [2] 47 bb }

  condition:
    any of them
}