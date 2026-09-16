rule TTP_XOR_WriteProcessMemory_bf58 {
  strings:
    $key_bf58 = { e8 2a [2] da 08 [2] dc 3d [2] f2 3d [2] cd 21 }

  condition:
    any of them
}