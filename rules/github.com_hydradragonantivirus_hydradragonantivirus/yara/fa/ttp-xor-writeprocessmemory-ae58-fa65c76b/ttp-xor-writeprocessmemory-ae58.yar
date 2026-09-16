rule TTP_XOR_WriteProcessMemory_ae58 {
  strings:
    $key_ae58 = { f9 2a [2] cb 08 [2] cd 3d [2] e3 3d [2] dc 21 }

  condition:
    any of them
}