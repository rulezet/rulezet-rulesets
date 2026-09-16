rule TTP_XOR_WriteProcessMemory_08db {
  strings:
    $key_08db = { 5f a9 [2] 6d 8b [2] 6b be [2] 45 be [2] 7a a2 }

  condition:
    any of them
}