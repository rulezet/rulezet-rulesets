rule TTP_XOR_WriteProcessMemory_aec8 {
  strings:
    $key_aec8 = { f9 ba [2] cb 98 [2] cd ad [2] e3 ad [2] dc b1 }

  condition:
    any of them
}