rule TTP_XOR_WriteProcessMemory_1f9e {
  strings:
    $key_1f9e = { 48 ec [2] 7a ce [2] 7c fb [2] 52 fb [2] 6d e7 }

  condition:
    any of them
}