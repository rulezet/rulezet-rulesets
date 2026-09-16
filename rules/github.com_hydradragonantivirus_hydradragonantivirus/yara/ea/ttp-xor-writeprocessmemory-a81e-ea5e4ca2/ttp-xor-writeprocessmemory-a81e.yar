rule TTP_XOR_WriteProcessMemory_a81e {
  strings:
    $key_a81e = { ff 6c [2] cd 4e [2] cb 7b [2] e5 7b [2] da 67 }

  condition:
    any of them
}