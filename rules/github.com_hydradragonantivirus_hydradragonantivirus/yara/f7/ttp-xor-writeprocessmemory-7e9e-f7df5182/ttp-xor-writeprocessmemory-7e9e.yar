rule TTP_XOR_WriteProcessMemory_7e9e {
  strings:
    $key_7e9e = { 29 ec [2] 1b ce [2] 1d fb [2] 33 fb [2] 0c e7 }

  condition:
    any of them
}