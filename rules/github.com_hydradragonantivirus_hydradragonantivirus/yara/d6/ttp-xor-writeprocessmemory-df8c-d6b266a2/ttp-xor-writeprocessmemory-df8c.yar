rule TTP_XOR_WriteProcessMemory_df8c {
  strings:
    $key_df8c = { 88 fe [2] ba dc [2] bc e9 [2] 92 e9 [2] ad f5 }

  condition:
    any of them
}