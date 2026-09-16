rule TTP_XOR_WriteProcessMemory_df6a {
  strings:
    $key_df6a = { 88 18 [2] ba 3a [2] bc 0f [2] 92 0f [2] ad 13 }

  condition:
    any of them
}