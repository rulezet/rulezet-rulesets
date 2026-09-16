rule TTP_XOR_WriteProcessMemory_1e9e {
  strings:
    $key_1e9e = { 49 ec [2] 7b ce [2] 7d fb [2] 53 fb [2] 6c e7 }

  condition:
    any of them
}