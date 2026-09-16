rule TTP_XOR_WriteProcessMemory_f776 {
  strings:
    $key_f776 = { a0 04 [2] 92 26 [2] 94 13 [2] ba 13 [2] 85 0f }

  condition:
    any of them
}