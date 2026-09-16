rule TTP_XOR_WriteProcessMemory_199e {
  strings:
    $key_199e = { 4e ec [2] 7c ce [2] 7a fb [2] 54 fb [2] 6b e7 }

  condition:
    any of them
}