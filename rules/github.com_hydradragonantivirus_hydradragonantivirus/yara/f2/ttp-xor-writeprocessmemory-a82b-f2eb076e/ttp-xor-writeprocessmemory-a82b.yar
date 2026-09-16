rule TTP_XOR_WriteProcessMemory_a82b {
  strings:
    $key_a82b = { ff 59 [2] cd 7b [2] cb 4e [2] e5 4e [2] da 52 }

  condition:
    any of them
}