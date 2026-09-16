rule TTP_XOR_WriteProcessMemory_a864 {
  strings:
    $key_a864 = { ff 16 [2] cd 34 [2] cb 01 [2] e5 01 [2] da 1d }

  condition:
    any of them
}