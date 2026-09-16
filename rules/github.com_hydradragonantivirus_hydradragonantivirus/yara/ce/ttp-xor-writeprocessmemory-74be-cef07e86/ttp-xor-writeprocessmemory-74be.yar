rule TTP_XOR_WriteProcessMemory_74be {
  strings:
    $key_74be = { 23 cc [2] 11 ee [2] 17 db [2] 39 db [2] 06 c7 }

  condition:
    any of them
}