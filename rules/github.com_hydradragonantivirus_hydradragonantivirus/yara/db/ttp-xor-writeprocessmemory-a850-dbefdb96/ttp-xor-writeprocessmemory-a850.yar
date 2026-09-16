rule TTP_XOR_WriteProcessMemory_a850 {
  strings:
    $key_a850 = { ff 22 [2] cd 00 [2] cb 35 [2] e5 35 [2] da 29 }

  condition:
    any of them
}