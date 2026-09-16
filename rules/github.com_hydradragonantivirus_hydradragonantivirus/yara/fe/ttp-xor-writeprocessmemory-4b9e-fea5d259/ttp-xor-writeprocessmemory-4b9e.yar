rule TTP_XOR_WriteProcessMemory_4b9e {
  strings:
    $key_4b9e = { 1c ec [2] 2e ce [2] 28 fb [2] 06 fb [2] 39 e7 }

  condition:
    any of them
}