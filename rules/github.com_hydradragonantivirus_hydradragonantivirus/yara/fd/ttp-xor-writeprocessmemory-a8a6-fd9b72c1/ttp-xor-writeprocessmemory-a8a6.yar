rule TTP_XOR_WriteProcessMemory_a8a6 {
  strings:
    $key_a8a6 = { ff d4 [2] cd f6 [2] cb c3 [2] e5 c3 [2] da df }

  condition:
    any of them
}