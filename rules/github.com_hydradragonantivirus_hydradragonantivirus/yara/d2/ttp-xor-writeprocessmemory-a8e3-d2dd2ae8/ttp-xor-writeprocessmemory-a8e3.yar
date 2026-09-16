rule TTP_XOR_WriteProcessMemory_a8e3 {
  strings:
    $key_a8e3 = { ff 91 [2] cd b3 [2] cb 86 [2] e5 86 [2] da 9a }

  condition:
    any of them
}