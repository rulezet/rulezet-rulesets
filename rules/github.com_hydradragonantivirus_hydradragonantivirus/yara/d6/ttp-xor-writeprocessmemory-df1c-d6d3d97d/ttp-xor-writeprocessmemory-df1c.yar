rule TTP_XOR_WriteProcessMemory_df1c {
  strings:
    $key_df1c = { 88 6e [2] ba 4c [2] bc 79 [2] 92 79 [2] ad 65 }

  condition:
    any of them
}