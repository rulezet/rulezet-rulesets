rule TTP_XOR_WriteProcessMemory_a830 {
  strings:
    $key_a830 = { ff 42 [2] cd 60 [2] cb 55 [2] e5 55 [2] da 49 }

  condition:
    any of them
}