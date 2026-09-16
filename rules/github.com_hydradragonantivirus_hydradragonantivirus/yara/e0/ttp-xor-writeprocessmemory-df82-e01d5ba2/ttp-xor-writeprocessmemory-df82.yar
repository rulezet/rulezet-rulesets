rule TTP_XOR_WriteProcessMemory_df82 {
  strings:
    $key_df82 = { 88 f0 [2] ba d2 [2] bc e7 [2] 92 e7 [2] ad fb }

  condition:
    any of them
}