rule TTP_XOR_WriteProcessMemory_139e {
  strings:
    $key_139e = { 44 ec [2] 76 ce [2] 70 fb [2] 5e fb [2] 61 e7 }

  condition:
    any of them
}