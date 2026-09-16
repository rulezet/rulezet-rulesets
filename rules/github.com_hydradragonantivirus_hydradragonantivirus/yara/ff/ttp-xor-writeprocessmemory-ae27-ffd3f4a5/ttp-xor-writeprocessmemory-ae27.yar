rule TTP_XOR_WriteProcessMemory_ae27 {
  strings:
    $key_ae27 = { f9 55 [2] cb 77 [2] cd 42 [2] e3 42 [2] dc 5e }

  condition:
    any of them
}