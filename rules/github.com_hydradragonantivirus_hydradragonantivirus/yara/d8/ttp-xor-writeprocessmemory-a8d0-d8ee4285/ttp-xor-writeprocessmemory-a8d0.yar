rule TTP_XOR_WriteProcessMemory_a8d0 {
  strings:
    $key_a8d0 = { ff a2 [2] cd 80 [2] cb b5 [2] e5 b5 [2] da a9 }

  condition:
    any of them
}