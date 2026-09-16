rule TTP_XOR_WriteProcessMemory_df09 {
  strings:
    $key_df09 = { 88 7b [2] ba 59 [2] bc 6c [2] 92 6c [2] ad 70 }

  condition:
    any of them
}