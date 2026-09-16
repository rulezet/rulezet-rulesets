rule TTP_XOR_WriteProcessMemory_399e {
  strings:
    $key_399e = { 6e ec [2] 5c ce [2] 5a fb [2] 74 fb [2] 4b e7 }

  condition:
    any of them
}