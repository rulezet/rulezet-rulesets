rule TTP_XOR_WriteProcessMemory_aedf {
  strings:
    $key_aedf = { f9 ad [2] cb 8f [2] cd ba [2] e3 ba [2] dc a6 }

  condition:
    any of them
}