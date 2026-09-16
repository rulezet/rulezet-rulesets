rule TTP_XOR_WriteProcessMemory_a8db {
  strings:
    $key_a8db = { ff a9 [2] cd 8b [2] cb be [2] e5 be [2] da a2 }

  condition:
    any of them
}