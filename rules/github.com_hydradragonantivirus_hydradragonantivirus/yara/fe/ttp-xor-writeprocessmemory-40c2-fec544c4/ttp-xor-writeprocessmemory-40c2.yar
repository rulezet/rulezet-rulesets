rule TTP_XOR_WriteProcessMemory_40c2 {
  strings:
    $key_40c2 = { 17 b0 [2] 25 92 [2] 23 a7 [2] 0d a7 [2] 32 bb }

  condition:
    any of them
}