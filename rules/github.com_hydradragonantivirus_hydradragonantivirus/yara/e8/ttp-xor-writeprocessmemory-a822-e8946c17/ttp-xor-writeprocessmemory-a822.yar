rule TTP_XOR_WriteProcessMemory_a822 {
  strings:
    $key_a822 = { ff 50 [2] cd 72 [2] cb 47 [2] e5 47 [2] da 5b }

  condition:
    any of them
}