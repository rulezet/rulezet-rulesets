rule TTP_XOR_WriteProcessMemory_a846 {
  strings:
    $key_a846 = { ff 34 [2] cd 16 [2] cb 23 [2] e5 23 [2] da 3f }

  condition:
    any of them
}