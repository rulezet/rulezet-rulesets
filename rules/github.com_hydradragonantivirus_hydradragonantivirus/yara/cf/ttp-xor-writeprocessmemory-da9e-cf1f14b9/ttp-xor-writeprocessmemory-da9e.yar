rule TTP_XOR_WriteProcessMemory_da9e {
  strings:
    $key_da9e = { 8d ec [2] bf ce [2] b9 fb [2] 97 fb [2] a8 e7 }

  condition:
    any of them
}