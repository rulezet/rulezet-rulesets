rule TTP_XOR_WriteProcessMemory_18db {
  strings:
    $key_18db = { 4f a9 [2] 7d 8b [2] 7b be [2] 55 be [2] 6a a2 }

  condition:
    any of them
}