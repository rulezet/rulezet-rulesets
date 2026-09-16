rule TTP_XOR_WriteProcessMemory_ae57 {
  strings:
    $key_ae57 = { f9 25 [2] cb 07 [2] cd 32 [2] e3 32 [2] dc 2e }

  condition:
    any of them
}