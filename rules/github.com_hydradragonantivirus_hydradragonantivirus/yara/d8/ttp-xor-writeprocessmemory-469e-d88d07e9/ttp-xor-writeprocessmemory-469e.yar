rule TTP_XOR_WriteProcessMemory_469e {
  strings:
    $key_469e = { 11 ec [2] 23 ce [2] 25 fb [2] 0b fb [2] 34 e7 }

  condition:
    any of them
}