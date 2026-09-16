rule TTP_XOR_WriteProcessMemory_359e {
  strings:
    $key_359e = { 62 ec [2] 50 ce [2] 56 fb [2] 78 fb [2] 47 e7 }

  condition:
    any of them
}