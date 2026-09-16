rule TTP_XOR_WriteProcessMemory_df46 {
  strings:
    $key_df46 = { 88 34 [2] ba 16 [2] bc 23 [2] 92 23 [2] ad 3f }

  condition:
    any of them
}