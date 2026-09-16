rule TTP_XOR_WriteProcessMemory_ae34 {
  strings:
    $key_ae34 = { f9 46 [2] cb 64 [2] cd 51 [2] e3 51 [2] dc 4d }

  condition:
    any of them
}