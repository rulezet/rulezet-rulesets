rule TTP_XOR_WriteProcessMemory_df0e {
  strings:
    $key_df0e = { 88 7c [2] ba 5e [2] bc 6b [2] 92 6b [2] ad 77 }

  condition:
    any of them
}