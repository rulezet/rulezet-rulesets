rule TTP_XOR_WriteProcessMemory_16ab {
  strings:
    $key_16ab = { 41 d9 [2] 73 fb [2] 75 ce [2] 5b ce [2] 64 d2 }

  condition:
    any of them
}