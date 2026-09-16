rule TTP_XOR_WriteProcessMemory_df88 {
  strings:
    $key_df88 = { 88 fa [2] ba d8 [2] bc ed [2] 92 ed [2] ad f1 }

  condition:
    any of them
}