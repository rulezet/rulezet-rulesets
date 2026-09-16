rule TTP_XOR_WriteProcessMemory_ae65 {
  strings:
    $key_ae65 = { f9 17 [2] cb 35 [2] cd 00 [2] e3 00 [2] dc 1c }

  condition:
    any of them
}