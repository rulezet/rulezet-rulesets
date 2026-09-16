rule TTP_XOR_WriteProcessMemory_df20 {
  strings:
    $key_df20 = { 88 52 [2] ba 70 [2] bc 45 [2] 92 45 [2] ad 59 }

  condition:
    any of them
}