rule TTP_XOR_WriteProcessMemory_089e {
  strings:
    $key_089e = { 5f ec [2] 6d ce [2] 6b fb [2] 45 fb [2] 7a e7 }

  condition:
    any of them
}