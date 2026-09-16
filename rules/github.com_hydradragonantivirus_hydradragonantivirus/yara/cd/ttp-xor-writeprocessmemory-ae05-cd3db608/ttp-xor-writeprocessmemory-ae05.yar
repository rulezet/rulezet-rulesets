rule TTP_XOR_WriteProcessMemory_ae05 {
  strings:
    $key_ae05 = { f9 77 [2] cb 55 [2] cd 60 [2] e3 60 [2] dc 7c }

  condition:
    any of them
}