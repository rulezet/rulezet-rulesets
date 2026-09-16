rule TTP_XOR_WriteProcessMemory_80bc {
  strings:
    $key_80bc = { d7 ce [2] e5 ec [2] e3 d9 [2] cd d9 [2] f2 c5 }

  condition:
    any of them
}