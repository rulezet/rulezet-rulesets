rule TTP_XOR_WriteProcessMemory_a8f0 {
  strings:
    $key_a8f0 = { ff 82 [2] cd a0 [2] cb 95 [2] e5 95 [2] da 89 }

  condition:
    any of them
}