rule TTP_XOR_WriteProcessMemory_aec7 {
  strings:
    $key_aec7 = { f9 b5 [2] cb 97 [2] cd a2 [2] e3 a2 [2] dc be }

  condition:
    any of them
}