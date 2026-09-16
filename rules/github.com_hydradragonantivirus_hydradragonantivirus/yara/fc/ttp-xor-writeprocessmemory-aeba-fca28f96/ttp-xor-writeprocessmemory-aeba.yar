rule TTP_XOR_WriteProcessMemory_aeba {
  strings:
    $key_aeba = { f9 c8 [2] cb ea [2] cd df [2] e3 df [2] dc c3 }

  condition:
    any of them
}