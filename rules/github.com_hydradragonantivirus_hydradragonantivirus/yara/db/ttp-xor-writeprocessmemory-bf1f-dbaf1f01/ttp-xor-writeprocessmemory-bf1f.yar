rule TTP_XOR_WriteProcessMemory_bf1f {
  strings:
    $key_bf1f = { e8 6d [2] da 4f [2] dc 7a [2] f2 7a [2] cd 66 }

  condition:
    any of them
}