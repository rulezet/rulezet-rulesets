rule TTP_XOR_WriteProcessMemory_3b9e {
  strings:
    $key_3b9e = { 6c ec [2] 5e ce [2] 58 fb [2] 76 fb [2] 49 e7 }

  condition:
    any of them
}