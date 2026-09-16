rule TTP_XOR_WriteProcessMemory_449e {
  strings:
    $key_449e = { 13 ec [2] 21 ce [2] 27 fb [2] 09 fb [2] 36 e7 }

  condition:
    any of them
}