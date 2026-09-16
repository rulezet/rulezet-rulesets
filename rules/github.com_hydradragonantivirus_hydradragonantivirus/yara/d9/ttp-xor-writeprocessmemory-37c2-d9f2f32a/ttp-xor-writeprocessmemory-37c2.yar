rule TTP_XOR_WriteProcessMemory_37c2 {
  strings:
    $key_37c2 = { 60 b0 [2] 52 92 [2] 54 a7 [2] 7a a7 [2] 45 bb }

  condition:
    any of them
}