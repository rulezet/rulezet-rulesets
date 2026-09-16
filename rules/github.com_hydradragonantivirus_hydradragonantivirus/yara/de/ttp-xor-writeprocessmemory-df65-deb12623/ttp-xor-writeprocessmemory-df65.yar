rule TTP_XOR_WriteProcessMemory_df65 {
  strings:
    $key_df65 = { 88 17 [2] ba 35 [2] bc 00 [2] 92 00 [2] ad 1c }

  condition:
    any of them
}