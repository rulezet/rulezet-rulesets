rule TTP_XOR_WriteProcessMemory_31c2 {
  strings:
    $key_31c2 = { 66 b0 [2] 54 92 [2] 52 a7 [2] 7c a7 [2] 43 bb }

  condition:
    any of them
}