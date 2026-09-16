rule TTP_XOR_WriteProcessMemory_a80b {
  strings:
    $key_a80b = { ff 79 [2] cd 5b [2] cb 6e [2] e5 6e [2] da 72 }

  condition:
    any of them
}