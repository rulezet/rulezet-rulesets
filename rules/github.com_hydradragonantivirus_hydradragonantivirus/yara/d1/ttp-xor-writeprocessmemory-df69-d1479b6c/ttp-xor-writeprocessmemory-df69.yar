rule TTP_XOR_WriteProcessMemory_df69 {
  strings:
    $key_df69 = { 88 1b [2] ba 39 [2] bc 0c [2] 92 0c [2] ad 10 }

  condition:
    any of them
}