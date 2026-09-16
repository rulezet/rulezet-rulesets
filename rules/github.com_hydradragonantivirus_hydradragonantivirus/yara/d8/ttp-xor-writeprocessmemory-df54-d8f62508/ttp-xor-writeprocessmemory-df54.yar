rule TTP_XOR_WriteProcessMemory_df54 {
  strings:
    $key_df54 = { 88 26 [2] ba 04 [2] bc 31 [2] 92 31 [2] ad 2d }

  condition:
    any of them
}