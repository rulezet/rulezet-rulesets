rule TTP_XOR_WriteProcessMemory_80db {
  strings:
    $key_80db = { d7 a9 [2] e5 8b [2] e3 be [2] cd be [2] f2 a2 }

  condition:
    any of them
}