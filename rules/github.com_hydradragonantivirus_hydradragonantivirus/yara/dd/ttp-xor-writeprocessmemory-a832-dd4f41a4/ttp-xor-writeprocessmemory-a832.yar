rule TTP_XOR_WriteProcessMemory_a832 {
  strings:
    $key_a832 = { ff 40 [2] cd 62 [2] cb 57 [2] e5 57 [2] da 4b }

  condition:
    any of them
}