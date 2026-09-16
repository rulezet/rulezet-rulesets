rule TTP_XOR_WriteProcessMemory_f1c2 {
  strings:
    $key_f1c2 = { a6 b0 [2] 94 92 [2] 92 a7 [2] bc a7 [2] 83 bb }

  condition:
    any of them
}