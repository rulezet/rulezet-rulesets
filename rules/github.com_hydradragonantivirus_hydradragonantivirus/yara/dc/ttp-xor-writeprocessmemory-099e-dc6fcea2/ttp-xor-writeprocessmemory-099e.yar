rule TTP_XOR_WriteProcessMemory_099e {
  strings:
    $key_099e = { 5e ec [2] 6c ce [2] 6a fb [2] 44 fb [2] 7b e7 }

  condition:
    any of them
}