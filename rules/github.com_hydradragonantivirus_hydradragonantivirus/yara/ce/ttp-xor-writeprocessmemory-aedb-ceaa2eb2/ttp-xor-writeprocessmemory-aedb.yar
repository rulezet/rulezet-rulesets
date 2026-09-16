rule TTP_XOR_WriteProcessMemory_aedb {
  strings:
    $key_aedb = { f9 a9 [2] cb 8b [2] cd be [2] e3 be [2] dc a2 }

  condition:
    any of them
}