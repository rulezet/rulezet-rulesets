rule TTP_XOR_WriteProcessMemory_df49 {
  strings:
    $key_df49 = { 88 3b [2] ba 19 [2] bc 2c [2] 92 2c [2] ad 30 }

  condition:
    any of them
}