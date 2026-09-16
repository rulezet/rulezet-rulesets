rule TTP_XOR_WriteProcessMemory_a853 {
  strings:
    $key_a853 = { ff 21 [2] cd 03 [2] cb 36 [2] e5 36 [2] da 2a }

  condition:
    any of them
}