rule TTP_XOR_WriteProcessMemory_e776 {
  strings:
    $key_e776 = { b0 04 [2] 82 26 [2] 84 13 [2] aa 13 [2] 95 0f }

  condition:
    any of them
}