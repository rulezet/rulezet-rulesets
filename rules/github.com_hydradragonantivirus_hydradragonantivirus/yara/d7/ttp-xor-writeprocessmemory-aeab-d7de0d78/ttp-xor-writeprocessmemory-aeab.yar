rule TTP_XOR_WriteProcessMemory_aeab {
  strings:
    $key_aeab = { f9 d9 [2] cb fb [2] cd ce [2] e3 ce [2] dc d2 }

  condition:
    any of them
}