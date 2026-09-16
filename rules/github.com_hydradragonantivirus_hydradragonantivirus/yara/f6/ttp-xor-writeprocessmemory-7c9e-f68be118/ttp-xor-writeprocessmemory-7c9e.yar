rule TTP_XOR_WriteProcessMemory_7c9e {
  strings:
    $key_7c9e = { 2b ec [2] 19 ce [2] 1f fb [2] 31 fb [2] 0e e7 }

  condition:
    any of them
}