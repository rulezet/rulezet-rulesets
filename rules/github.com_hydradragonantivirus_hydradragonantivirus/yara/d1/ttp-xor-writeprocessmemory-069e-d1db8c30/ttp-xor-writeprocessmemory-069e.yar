rule TTP_XOR_WriteProcessMemory_069e {
  strings:
    $key_069e = { 51 ec [2] 63 ce [2] 65 fb [2] 4b fb [2] 74 e7 }

  condition:
    any of them
}