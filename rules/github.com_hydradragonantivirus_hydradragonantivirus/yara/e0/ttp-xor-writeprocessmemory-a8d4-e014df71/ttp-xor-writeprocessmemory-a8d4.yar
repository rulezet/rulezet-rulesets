rule TTP_XOR_WriteProcessMemory_a8d4 {
  strings:
    $key_a8d4 = { ff a6 [2] cd 84 [2] cb b1 [2] e5 b1 [2] da ad }

  condition:
    any of them
}