rule TTP_XOR_WriteProcessMemory_aec2 {
  strings:
    $key_aec2 = { f9 b0 [2] cb 92 [2] cd a7 [2] e3 a7 [2] dc bb }

  condition:
    any of them
}