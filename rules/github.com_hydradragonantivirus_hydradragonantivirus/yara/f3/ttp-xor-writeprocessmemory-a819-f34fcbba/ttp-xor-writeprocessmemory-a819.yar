rule TTP_XOR_WriteProcessMemory_a819 {
  strings:
    $key_a819 = { ff 6b [2] cd 49 [2] cb 7c [2] e5 7c [2] da 60 }

  condition:
    any of them
}