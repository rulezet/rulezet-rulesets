rule TTP_XOR_WriteProcessMemory_729e {
  strings:
    $key_729e = { 25 ec [2] 17 ce [2] 11 fb [2] 3f fb [2] 00 e7 }

  condition:
    any of them
}