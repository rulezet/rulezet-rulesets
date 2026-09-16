rule TTP_XOR_WriteProcessMemory_a808 {
  strings:
    $key_a808 = { ff 7a [2] cd 58 [2] cb 6d [2] e5 6d [2] da 71 }

  condition:
    any of them
}