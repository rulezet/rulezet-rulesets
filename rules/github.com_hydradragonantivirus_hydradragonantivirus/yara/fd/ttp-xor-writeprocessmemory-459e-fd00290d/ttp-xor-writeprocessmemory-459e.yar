rule TTP_XOR_WriteProcessMemory_459e {
  strings:
    $key_459e = { 12 ec [2] 20 ce [2] 26 fb [2] 08 fb [2] 37 e7 }

  condition:
    any of them
}