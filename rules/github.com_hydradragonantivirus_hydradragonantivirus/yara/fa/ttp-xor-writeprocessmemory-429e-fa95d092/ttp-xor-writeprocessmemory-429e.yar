rule TTP_XOR_WriteProcessMemory_429e {
  strings:
    $key_429e = { 15 ec [2] 27 ce [2] 21 fb [2] 0f fb [2] 30 e7 }

  condition:
    any of them
}