rule TTP_XOR_WriteProcessMemory_4e9e {
  strings:
    $key_4e9e = { 19 ec [2] 2b ce [2] 2d fb [2] 03 fb [2] 3c e7 }

  condition:
    any of them
}