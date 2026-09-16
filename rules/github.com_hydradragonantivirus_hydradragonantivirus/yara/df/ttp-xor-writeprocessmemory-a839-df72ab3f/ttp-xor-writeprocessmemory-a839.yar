rule TTP_XOR_WriteProcessMemory_a839 {
  strings:
    $key_a839 = { ff 4b [2] cd 69 [2] cb 5c [2] e5 5c [2] da 40 }

  condition:
    any of them
}