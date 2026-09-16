rule TTP_XOR_WriteProcessMemory_1c9e {
  strings:
    $key_1c9e = { 4b ec [2] 79 ce [2] 7f fb [2] 51 fb [2] 6e e7 }

  condition:
    any of them
}