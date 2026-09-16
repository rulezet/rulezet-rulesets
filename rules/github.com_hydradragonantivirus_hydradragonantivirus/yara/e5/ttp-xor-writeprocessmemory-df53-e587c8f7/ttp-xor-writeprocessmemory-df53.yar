rule TTP_XOR_WriteProcessMemory_df53 {
  strings:
    $key_df53 = { 88 21 [2] ba 03 [2] bc 36 [2] 92 36 [2] ad 2a }

  condition:
    any of them
}