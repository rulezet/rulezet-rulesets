rule TTP_XOR_WriteProcessMemory_409e {
  strings:
    $key_409e = { 17 ec [2] 25 ce [2] 23 fb [2] 0d fb [2] 32 e7 }

  condition:
    any of them
}