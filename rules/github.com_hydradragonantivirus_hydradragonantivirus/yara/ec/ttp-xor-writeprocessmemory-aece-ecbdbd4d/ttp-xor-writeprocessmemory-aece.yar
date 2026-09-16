rule TTP_XOR_WriteProcessMemory_aece {
  strings:
    $key_aece = { f9 bc [2] cb 9e [2] cd ab [2] e3 ab [2] dc b7 }

  condition:
    any of them
}