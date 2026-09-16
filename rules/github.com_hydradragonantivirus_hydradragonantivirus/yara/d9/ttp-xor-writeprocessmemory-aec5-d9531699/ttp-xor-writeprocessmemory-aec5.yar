rule TTP_XOR_WriteProcessMemory_aec5 {
  strings:
    $key_aec5 = { f9 b7 [2] cb 95 [2] cd a0 [2] e3 a0 [2] dc bc }

  condition:
    any of them
}