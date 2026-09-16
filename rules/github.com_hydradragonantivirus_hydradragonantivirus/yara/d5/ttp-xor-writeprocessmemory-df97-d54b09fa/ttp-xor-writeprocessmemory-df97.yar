rule TTP_XOR_WriteProcessMemory_df97 {
  strings:
    $key_df97 = { 88 e5 [2] ba c7 [2] bc f2 [2] 92 f2 [2] ad ee }

  condition:
    any of them
}