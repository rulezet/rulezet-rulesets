rule TTP_XOR_WriteProcessMemory_57ab {
  strings:
    $key_57ab = { 00 d9 [2] 32 fb [2] 34 ce [2] 1a ce [2] 25 d2 }

  condition:
    any of them
}