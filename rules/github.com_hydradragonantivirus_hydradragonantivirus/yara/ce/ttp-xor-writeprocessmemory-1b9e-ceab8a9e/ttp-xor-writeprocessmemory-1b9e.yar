rule TTP_XOR_WriteProcessMemory_1b9e {
  strings:
    $key_1b9e = { 4c ec [2] 7e ce [2] 78 fb [2] 56 fb [2] 69 e7 }

  condition:
    any of them
}