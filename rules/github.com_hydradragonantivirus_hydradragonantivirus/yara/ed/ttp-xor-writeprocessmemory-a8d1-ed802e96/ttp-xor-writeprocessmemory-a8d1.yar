rule TTP_XOR_WriteProcessMemory_a8d1 {
  strings:
    $key_a8d1 = { ff a3 [2] cd 81 [2] cb b4 [2] e5 b4 [2] da a8 }

  condition:
    any of them
}