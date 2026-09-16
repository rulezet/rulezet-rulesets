rule TTP_XOR_WriteProcessMemory_a856 {
  strings:
    $key_a856 = { ff 24 [2] cd 06 [2] cb 33 [2] e5 33 [2] da 2f }

  condition:
    any of them
}