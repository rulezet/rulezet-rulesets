rule TTP_XOR_WriteProcessMemory_df8b {
  strings:
    $key_df8b = { 88 f9 [2] ba db [2] bc ee [2] 92 ee [2] ad f2 }

  condition:
    any of them
}