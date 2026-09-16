rule TTP_XOR_WriteProcessMemory_a82a {
  strings:
    $key_a82a = { ff 58 [2] cd 7a [2] cb 4f [2] e5 4f [2] da 53 }

  condition:
    any of them
}