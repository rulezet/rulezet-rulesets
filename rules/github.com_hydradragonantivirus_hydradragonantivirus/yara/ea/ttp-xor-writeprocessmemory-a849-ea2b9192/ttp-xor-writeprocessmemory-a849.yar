rule TTP_XOR_WriteProcessMemory_a849 {
  strings:
    $key_a849 = { ff 3b [2] cd 19 [2] cb 2c [2] e5 2c [2] da 30 }

  condition:
    any of them
}