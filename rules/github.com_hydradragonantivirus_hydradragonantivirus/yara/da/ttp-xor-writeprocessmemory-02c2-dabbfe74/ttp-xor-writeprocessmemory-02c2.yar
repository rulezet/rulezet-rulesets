rule TTP_XOR_WriteProcessMemory_02c2 {
  strings:
    $key_02c2 = { 55 b0 [2] 67 92 [2] 61 a7 [2] 4f a7 [2] 70 bb }

  condition:
    any of them
}