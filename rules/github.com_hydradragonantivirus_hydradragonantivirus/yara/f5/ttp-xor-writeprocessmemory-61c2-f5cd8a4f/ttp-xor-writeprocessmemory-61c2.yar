rule TTP_XOR_WriteProcessMemory_61c2 {
  strings:
    $key_61c2 = { 36 b0 [2] 04 92 [2] 02 a7 [2] 2c a7 [2] 13 bb }

  condition:
    any of them
}