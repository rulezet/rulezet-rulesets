rule TTP_XOR_WriteProcessMemory_aeeb {
  strings:
    $key_aeeb = { f9 99 [2] cb bb [2] cd 8e [2] e3 8e [2] dc 92 }

  condition:
    any of them
}