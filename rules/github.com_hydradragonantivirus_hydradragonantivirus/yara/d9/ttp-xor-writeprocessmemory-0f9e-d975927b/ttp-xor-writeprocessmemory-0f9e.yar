rule TTP_XOR_WriteProcessMemory_0f9e {
  strings:
    $key_0f9e = { 58 ec [2] 6a ce [2] 6c fb [2] 42 fb [2] 7d e7 }

  condition:
    any of them
}