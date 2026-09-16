rule TTP_XOR_WriteProcessMemory_aee4 {
  strings:
    $key_aee4 = { f9 96 [2] cb b4 [2] cd 81 [2] e3 81 [2] dc 9d }

  condition:
    any of them
}