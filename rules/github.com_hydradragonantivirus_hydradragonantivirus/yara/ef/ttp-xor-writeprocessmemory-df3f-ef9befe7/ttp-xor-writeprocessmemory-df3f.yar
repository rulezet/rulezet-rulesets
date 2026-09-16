rule TTP_XOR_WriteProcessMemory_df3f {
  strings:
    $key_df3f = { 88 4d [2] ba 6f [2] bc 5a [2] 92 5a [2] ad 46 }

  condition:
    any of them
}