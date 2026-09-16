rule TTP_XOR_WriteProcessMemory_419e {
  strings:
    $key_419e = { 16 ec [2] 24 ce [2] 22 fb [2] 0c fb [2] 33 e7 }

  condition:
    any of them
}