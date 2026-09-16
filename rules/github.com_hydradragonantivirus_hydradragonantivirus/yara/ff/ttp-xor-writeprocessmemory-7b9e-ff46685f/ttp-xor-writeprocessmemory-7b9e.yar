rule TTP_XOR_WriteProcessMemory_7b9e {
  strings:
    $key_7b9e = { 2c ec [2] 1e ce [2] 18 fb [2] 36 fb [2] 09 e7 }

  condition:
    any of them
}