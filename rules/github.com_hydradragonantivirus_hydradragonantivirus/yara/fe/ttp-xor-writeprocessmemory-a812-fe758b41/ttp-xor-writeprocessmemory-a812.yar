rule TTP_XOR_WriteProcessMemory_a812 {
  strings:
    $key_a812 = { ff 60 [2] cd 42 [2] cb 77 [2] e5 77 [2] da 6b }

  condition:
    any of them
}