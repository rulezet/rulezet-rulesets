rule TTP_XOR_WriteProcessMemory_aeb7 {
  strings:
    $key_aeb7 = { f9 c5 [2] cb e7 [2] cd d2 [2] e3 d2 [2] dc ce }

  condition:
    any of them
}