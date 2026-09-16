rule TTP_XOR_WriteProcessMemory_a8d5 {
  strings:
    $key_a8d5 = { ff a7 [2] cd 85 [2] cb b0 [2] e5 b0 [2] da ac }

  condition:
    any of them
}