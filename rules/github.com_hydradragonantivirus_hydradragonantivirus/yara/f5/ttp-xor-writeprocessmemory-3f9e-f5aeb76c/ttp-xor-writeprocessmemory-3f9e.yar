rule TTP_XOR_WriteProcessMemory_3f9e {
  strings:
    $key_3f9e = { 68 ec [2] 5a ce [2] 5c fb [2] 72 fb [2] 4d e7 }

  condition:
    any of them
}