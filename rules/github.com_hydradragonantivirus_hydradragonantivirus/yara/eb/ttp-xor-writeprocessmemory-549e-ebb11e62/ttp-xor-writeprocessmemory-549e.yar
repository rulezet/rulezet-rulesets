rule TTP_XOR_WriteProcessMemory_549e {
  strings:
    $key_549e = { 03 ec [2] 31 ce [2] 37 fb [2] 19 fb [2] 26 e7 }

  condition:
    any of them
}