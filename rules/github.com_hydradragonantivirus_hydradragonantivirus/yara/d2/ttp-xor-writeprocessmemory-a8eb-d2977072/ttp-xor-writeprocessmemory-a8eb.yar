rule TTP_XOR_WriteProcessMemory_a8eb {
  strings:
    $key_a8eb = { ff 99 [2] cd bb [2] cb 8e [2] e5 8e [2] da 92 }

  condition:
    any of them
}