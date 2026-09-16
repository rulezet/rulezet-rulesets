rule TTP_XOR_WriteProcessMemory_df43 {
  strings:
    $key_df43 = { 88 31 [2] ba 13 [2] bc 26 [2] 92 26 [2] ad 3a }

  condition:
    any of them
}