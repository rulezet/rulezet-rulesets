rule TTP_XOR_WriteProcessMemory_10be {
  strings:
    $key_10be = { 47 cc [2] 75 ee [2] 73 db [2] 5d db [2] 62 c7 }

  condition:
    any of them
}