rule TTP_XOR_WriteProcessMemory_aee2 {
  strings:
    $key_aee2 = { f9 90 [2] cb b2 [2] cd 87 [2] e3 87 [2] dc 9b }

  condition:
    any of them
}