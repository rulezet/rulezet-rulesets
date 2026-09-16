rule TTP_XOR_WriteProcessMemory_aeb8 {
  strings:
    $key_aeb8 = { f9 ca [2] cb e8 [2] cd dd [2] e3 dd [2] dc c1 }

  condition:
    any of them
}