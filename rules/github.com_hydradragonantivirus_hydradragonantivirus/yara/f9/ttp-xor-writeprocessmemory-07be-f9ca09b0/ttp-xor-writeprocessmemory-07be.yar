rule TTP_XOR_WriteProcessMemory_07be {
  strings:
    $key_07be = { 50 cc [2] 62 ee [2] 64 db [2] 4a db [2] 75 c7 }

  condition:
    any of them
}