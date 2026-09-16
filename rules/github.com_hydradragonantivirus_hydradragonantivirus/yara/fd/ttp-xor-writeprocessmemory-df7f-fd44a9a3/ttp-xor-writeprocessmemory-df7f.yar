rule TTP_XOR_WriteProcessMemory_df7f {
  strings:
    $key_df7f = { 88 0d [2] ba 2f [2] bc 1a [2] 92 1a [2] ad 06 }

  condition:
    any of them
}