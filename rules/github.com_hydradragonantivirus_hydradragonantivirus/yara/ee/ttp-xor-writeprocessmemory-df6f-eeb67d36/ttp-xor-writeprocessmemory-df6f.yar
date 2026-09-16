rule TTP_XOR_WriteProcessMemory_df6f {
  strings:
    $key_df6f = { 88 1d [2] ba 3f [2] bc 0a [2] 92 0a [2] ad 16 }

  condition:
    any of them
}