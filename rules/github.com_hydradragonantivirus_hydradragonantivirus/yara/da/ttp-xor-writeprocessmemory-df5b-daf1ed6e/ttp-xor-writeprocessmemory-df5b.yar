rule TTP_XOR_WriteProcessMemory_df5b {
  strings:
    $key_df5b = { 88 29 [2] ba 0b [2] bc 3e [2] 92 3e [2] ad 22 }

  condition:
    any of them
}