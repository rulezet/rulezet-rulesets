rule TTP_XOR_WriteProcessMemory_a829 {
  strings:
    $key_a829 = { ff 5b [2] cd 79 [2] cb 4c [2] e5 4c [2] da 50 }

  condition:
    any of them
}