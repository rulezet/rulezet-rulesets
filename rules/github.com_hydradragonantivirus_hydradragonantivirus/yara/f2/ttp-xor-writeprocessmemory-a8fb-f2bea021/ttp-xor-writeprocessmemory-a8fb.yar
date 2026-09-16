rule TTP_XOR_WriteProcessMemory_a8fb {
  strings:
    $key_a8fb = { ff 89 [2] cd ab [2] cb 9e [2] e5 9e [2] da 82 }

  condition:
    any of them
}