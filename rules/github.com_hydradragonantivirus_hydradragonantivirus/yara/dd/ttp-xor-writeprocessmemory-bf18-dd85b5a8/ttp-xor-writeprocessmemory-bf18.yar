rule TTP_XOR_WriteProcessMemory_bf18 {
  strings:
    $key_bf18 = { e8 6a [2] da 48 [2] dc 7d [2] f2 7d [2] cd 61 }

  condition:
    any of them
}