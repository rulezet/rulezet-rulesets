rule TTP_XOR_WriteProcessMemory_a84b {
  strings:
    $key_a84b = { ff 39 [2] cd 1b [2] cb 2e [2] e5 2e [2] da 32 }

  condition:
    any of them
}