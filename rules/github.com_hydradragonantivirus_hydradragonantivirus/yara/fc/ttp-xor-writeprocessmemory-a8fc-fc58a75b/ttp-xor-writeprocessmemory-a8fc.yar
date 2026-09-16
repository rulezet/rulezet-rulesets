rule TTP_XOR_WriteProcessMemory_a8fc {
  strings:
    $key_a8fc = { ff 8e [2] cd ac [2] cb 99 [2] e5 99 [2] da 85 }

  condition:
    any of them
}