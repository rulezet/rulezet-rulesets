rule TTP_XOR_WriteProcessMemory_df79 {
  strings:
    $key_df79 = { 88 0b [2] ba 29 [2] bc 1c [2] 92 1c [2] ad 00 }

  condition:
    any of them
}