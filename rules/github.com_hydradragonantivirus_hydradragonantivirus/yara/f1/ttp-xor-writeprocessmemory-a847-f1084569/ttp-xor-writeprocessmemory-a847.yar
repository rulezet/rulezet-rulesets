rule TTP_XOR_WriteProcessMemory_a847 {
  strings:
    $key_a847 = { ff 35 [2] cd 17 [2] cb 22 [2] e5 22 [2] da 3e }

  condition:
    any of them
}