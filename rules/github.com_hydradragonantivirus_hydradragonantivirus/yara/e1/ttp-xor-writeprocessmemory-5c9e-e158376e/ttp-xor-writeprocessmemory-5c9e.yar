rule TTP_XOR_WriteProcessMemory_5c9e {
  strings:
    $key_5c9e = { 0b ec [2] 39 ce [2] 3f fb [2] 11 fb [2] 2e e7 }

  condition:
    any of them
}