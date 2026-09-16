rule TTP_XOR_WriteProcessMemory_df11 {
  strings:
    $key_df11 = { 88 63 [2] ba 41 [2] bc 74 [2] 92 74 [2] ad 68 }

  condition:
    any of them
}