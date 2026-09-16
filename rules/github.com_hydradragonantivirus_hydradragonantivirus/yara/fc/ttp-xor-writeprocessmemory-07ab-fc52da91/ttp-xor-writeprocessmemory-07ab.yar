rule TTP_XOR_WriteProcessMemory_07ab {
  strings:
    $key_07ab = { 50 d9 [2] 62 fb [2] 64 ce [2] 4a ce [2] 75 d2 }

  condition:
    any of them
}