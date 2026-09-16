rule TTP_XOR_WriteProcessMemory_df6d {
  strings:
    $key_df6d = { 88 1f [2] ba 3d [2] bc 08 [2] 92 08 [2] ad 14 }

  condition:
    any of them
}