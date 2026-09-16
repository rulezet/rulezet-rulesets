rule TTP_XOR_WriteProcessMemory_4776 {
  strings:
    $key_4776 = { 10 04 [2] 22 26 [2] 24 13 [2] 0a 13 [2] 35 0f }

  condition:
    any of them
}