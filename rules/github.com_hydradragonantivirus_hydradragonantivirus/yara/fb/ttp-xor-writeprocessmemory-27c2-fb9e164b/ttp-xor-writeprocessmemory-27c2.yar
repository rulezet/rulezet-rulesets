rule TTP_XOR_WriteProcessMemory_27c2 {
  strings:
    $key_27c2 = { 70 b0 [2] 42 92 [2] 44 a7 [2] 6a a7 [2] 55 bb }

  condition:
    any of them
}