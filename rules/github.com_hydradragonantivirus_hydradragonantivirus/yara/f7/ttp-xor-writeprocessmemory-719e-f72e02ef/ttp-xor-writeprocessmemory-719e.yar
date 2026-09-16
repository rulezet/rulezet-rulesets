rule TTP_XOR_WriteProcessMemory_719e {
  strings:
    $key_719e = { 26 ec [2] 14 ce [2] 12 fb [2] 3c fb [2] 03 e7 }

  condition:
    any of them
}