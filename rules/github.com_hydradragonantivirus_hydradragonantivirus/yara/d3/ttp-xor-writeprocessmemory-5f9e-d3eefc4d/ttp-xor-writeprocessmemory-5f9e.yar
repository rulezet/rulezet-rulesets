rule TTP_XOR_WriteProcessMemory_5f9e {
  strings:
    $key_5f9e = { 08 ec [2] 3a ce [2] 3c fb [2] 12 fb [2] 2d e7 }

  condition:
    any of them
}