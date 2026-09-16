rule TTP_XOR_WriteProcessMemory_aeb5 {
  strings:
    $key_aeb5 = { f9 c7 [2] cb e5 [2] cd d0 [2] e3 d0 [2] dc cc }

  condition:
    any of them
}