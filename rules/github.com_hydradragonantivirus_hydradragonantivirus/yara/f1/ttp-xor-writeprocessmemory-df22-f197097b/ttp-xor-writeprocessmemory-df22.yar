rule TTP_XOR_WriteProcessMemory_df22 {
  strings:
    $key_df22 = { 88 50 [2] ba 72 [2] bc 47 [2] 92 47 [2] ad 5b }

  condition:
    any of them
}