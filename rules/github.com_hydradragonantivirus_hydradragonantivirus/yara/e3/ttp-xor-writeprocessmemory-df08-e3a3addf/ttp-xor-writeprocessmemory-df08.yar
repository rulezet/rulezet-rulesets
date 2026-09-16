rule TTP_XOR_WriteProcessMemory_df08 {
  strings:
    $key_df08 = { 88 7a [2] ba 58 [2] bc 6d [2] 92 6d [2] ad 71 }

  condition:
    any of them
}