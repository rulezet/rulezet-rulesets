rule TTP_XOR_WriteProcessMemory_2f9e {
  strings:
    $key_2f9e = { 78 ec [2] 4a ce [2] 4c fb [2] 62 fb [2] 5d e7 }

  condition:
    any of them
}