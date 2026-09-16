rule TTP_XOR_WriteProcessMemory_a8ce {
  strings:
    $key_a8ce = { ff bc [2] cd 9e [2] cb ab [2] e5 ab [2] da b7 }

  condition:
    any of them
}