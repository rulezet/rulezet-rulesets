rule TTP_XOR_WriteProcessMemory_df23 {
  strings:
    $key_df23 = { 88 51 [2] ba 73 [2] bc 46 [2] 92 46 [2] ad 5a }

  condition:
    any of them
}