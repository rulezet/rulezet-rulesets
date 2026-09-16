rule TTP_XOR_WriteProcessMemory_42c2 {
  strings:
    $key_42c2 = { 15 b0 [2] 27 92 [2] 21 a7 [2] 0f a7 [2] 30 bb }

  condition:
    any of them
}