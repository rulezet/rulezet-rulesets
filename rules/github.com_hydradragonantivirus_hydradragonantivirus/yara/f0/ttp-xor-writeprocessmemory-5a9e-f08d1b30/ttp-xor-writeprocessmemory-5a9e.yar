rule TTP_XOR_WriteProcessMemory_5a9e {
  strings:
    $key_5a9e = { 0d ec [2] 3f ce [2] 39 fb [2] 17 fb [2] 28 e7 }

  condition:
    any of them
}