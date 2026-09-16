rule TTP_XOR_WriteProcessMemory_bfa3 {
  strings:
    $key_bfa3 = { e8 d1 [2] da f3 [2] dc c6 [2] f2 c6 [2] cd da }

  condition:
    any of them
}