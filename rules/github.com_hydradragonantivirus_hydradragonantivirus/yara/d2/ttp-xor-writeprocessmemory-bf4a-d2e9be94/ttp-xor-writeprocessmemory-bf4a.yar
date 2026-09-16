rule TTP_XOR_WriteProcessMemory_bf4a {
  strings:
    $key_bf4a = { e8 38 [2] da 1a [2] dc 2f [2] f2 2f [2] cd 33 }

  condition:
    any of them
}