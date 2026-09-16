rule TTP_XOR_WriteProcessMemory_a800 {
  strings:
    $key_a800 = { ff 72 [2] cd 50 [2] cb 65 [2] e5 65 [2] da 79 }

  condition:
    any of them
}