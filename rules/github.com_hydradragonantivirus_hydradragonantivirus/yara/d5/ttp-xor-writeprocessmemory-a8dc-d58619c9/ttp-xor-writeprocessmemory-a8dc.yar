rule TTP_XOR_WriteProcessMemory_a8dc {
  strings:
    $key_a8dc = { ff ae [2] cd 8c [2] cb b9 [2] e5 b9 [2] da a5 }

  condition:
    any of them
}