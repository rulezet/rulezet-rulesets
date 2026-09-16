rule TTP_XOR_WriteProcessMemory_a8f2 {
  strings:
    $key_a8f2 = { ff 80 [2] cd a2 [2] cb 97 [2] e5 97 [2] da 8b }

  condition:
    any of them
}