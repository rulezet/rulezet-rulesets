rule TTP_XOR_WriteProcessMemory_a875 {
  strings:
    $key_a875 = { ff 07 [2] cd 25 [2] cb 10 [2] e5 10 [2] da 0c }

  condition:
    any of them
}