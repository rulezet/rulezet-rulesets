rule TTP_XOR_WriteProcessMemory_a811 {
  strings:
    $key_a811 = { ff 63 [2] cd 41 [2] cb 74 [2] e5 74 [2] da 68 }

  condition:
    any of them
}