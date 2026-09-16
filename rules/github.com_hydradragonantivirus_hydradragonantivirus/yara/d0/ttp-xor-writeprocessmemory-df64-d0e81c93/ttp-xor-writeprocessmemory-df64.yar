rule TTP_XOR_WriteProcessMemory_df64 {
  strings:
    $key_df64 = { 88 16 [2] ba 34 [2] bc 01 [2] 92 01 [2] ad 1d }

  condition:
    any of them
}