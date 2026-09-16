rule TTP_XOR_WriteProcessMemory_ae94 {
  strings:
    $key_ae94 = { f9 e6 [2] cb c4 [2] cd f1 [2] e3 f1 [2] dc ed }

  condition:
    any of them
}