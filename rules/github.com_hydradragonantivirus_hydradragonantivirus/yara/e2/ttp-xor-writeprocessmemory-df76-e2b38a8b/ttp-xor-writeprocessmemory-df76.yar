rule TTP_XOR_WriteProcessMemory_df76 {
  strings:
    $key_df76 = { 88 04 [2] ba 26 [2] bc 13 [2] 92 13 [2] ad 0f }

  condition:
    any of them
}