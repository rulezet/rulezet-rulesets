rule TTP_XOR_WriteProcessMemory_a802 {
  strings:
    $key_a802 = { ff 70 [2] cd 52 [2] cb 67 [2] e5 67 [2] da 7b }

  condition:
    any of them
}