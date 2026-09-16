rule TTP_XOR_WriteProcessMemory_66c2 {
  strings:
    $key_66c2 = { 31 b0 [2] 03 92 [2] 05 a7 [2] 2b a7 [2] 14 bb }

  condition:
    any of them
}