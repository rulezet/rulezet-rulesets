rule TTP_XOR_WriteProcessMemory_f3c2 {
  strings:
    $key_f3c2 = { a4 b0 [2] 96 92 [2] 90 a7 [2] be a7 [2] 81 bb }

  condition:
    any of them
}