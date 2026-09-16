rule TTP_XOR_WriteProcessMemory_30c2 {
  strings:
    $key_30c2 = { 67 b0 [2] 55 92 [2] 53 a7 [2] 7d a7 [2] 42 bb }

  condition:
    any of them
}