rule TTP_XOR_WriteProcessMemory_7f9e {
  strings:
    $key_7f9e = { 28 ec [2] 1a ce [2] 1c fb [2] 32 fb [2] 0d e7 }

  condition:
    any of them
}