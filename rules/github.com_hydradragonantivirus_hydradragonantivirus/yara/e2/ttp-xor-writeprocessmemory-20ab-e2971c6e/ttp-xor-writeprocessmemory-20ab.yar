rule TTP_XOR_WriteProcessMemory_20ab {
  strings:
    $key_20ab = { 77 d9 [2] 45 fb [2] 43 ce [2] 6d ce [2] 52 d2 }

  condition:
    any of them
}