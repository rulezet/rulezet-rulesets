rule TTP_XOR_WriteProcessMemory_a8c5 {
  strings:
    $key_a8c5 = { ff b7 [2] cd 95 [2] cb a0 [2] e5 a0 [2] da bc }

  condition:
    any of them
}