rule TTP_XOR_WriteProcessMemory_5b9e {
  strings:
    $key_5b9e = { 0c ec [2] 3e ce [2] 38 fb [2] 16 fb [2] 29 e7 }

  condition:
    any of them
}