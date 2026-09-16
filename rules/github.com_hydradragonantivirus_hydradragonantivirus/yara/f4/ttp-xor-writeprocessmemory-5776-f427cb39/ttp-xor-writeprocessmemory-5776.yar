rule TTP_XOR_WriteProcessMemory_5776 {
  strings:
    $key_5776 = { 00 04 [2] 32 26 [2] 34 13 [2] 1a 13 [2] 25 0f }

  condition:
    any of them
}