rule TTP_XOR_WriteProcessMemory_df25 {
  strings:
    $key_df25 = { 88 57 [2] ba 75 [2] bc 40 [2] 92 40 [2] ad 5c }

  condition:
    any of them
}