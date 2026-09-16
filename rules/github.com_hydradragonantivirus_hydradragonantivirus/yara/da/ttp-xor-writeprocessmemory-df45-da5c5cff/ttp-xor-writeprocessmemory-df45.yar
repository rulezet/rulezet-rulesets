rule TTP_XOR_WriteProcessMemory_df45 {
  strings:
    $key_df45 = { 88 37 [2] ba 15 [2] bc 20 [2] 92 20 [2] ad 3c }

  condition:
    any of them
}