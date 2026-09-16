rule TTP_XOR_WriteProcessMemory_df83 {
  strings:
    $key_df83 = { 88 f1 [2] ba d3 [2] bc e6 [2] 92 e6 [2] ad fa }

  condition:
    any of them
}