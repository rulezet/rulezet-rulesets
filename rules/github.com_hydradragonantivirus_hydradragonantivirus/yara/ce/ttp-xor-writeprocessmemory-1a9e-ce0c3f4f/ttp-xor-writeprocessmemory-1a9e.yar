rule TTP_XOR_WriteProcessMemory_1a9e {
  strings:
    $key_1a9e = { 4d ec [2] 7f ce [2] 79 fb [2] 57 fb [2] 68 e7 }

  condition:
    any of them
}