rule TTP_XOR_WriteProcessMemory_df51 {
  strings:
    $key_df51 = { 88 23 [2] ba 01 [2] bc 34 [2] 92 34 [2] ad 28 }

  condition:
    any of them
}