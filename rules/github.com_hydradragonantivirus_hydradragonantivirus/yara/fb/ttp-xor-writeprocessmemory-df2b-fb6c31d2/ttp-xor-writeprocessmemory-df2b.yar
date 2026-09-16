rule TTP_XOR_WriteProcessMemory_df2b {
  strings:
    $key_df2b = { 88 59 [2] ba 7b [2] bc 4e [2] 92 4e [2] ad 52 }

  condition:
    any of them
}