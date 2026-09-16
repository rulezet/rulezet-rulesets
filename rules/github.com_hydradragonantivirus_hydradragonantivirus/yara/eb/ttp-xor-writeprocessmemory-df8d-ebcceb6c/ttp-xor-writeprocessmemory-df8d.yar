rule TTP_XOR_WriteProcessMemory_df8d {
  strings:
    $key_df8d = { 88 ff [2] ba dd [2] bc e8 [2] 92 e8 [2] ad f4 }

  condition:
    any of them
}