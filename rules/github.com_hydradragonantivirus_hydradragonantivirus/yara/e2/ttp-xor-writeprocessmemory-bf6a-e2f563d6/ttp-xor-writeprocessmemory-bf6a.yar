rule TTP_XOR_WriteProcessMemory_bf6a {
  strings:
    $key_bf6a = { e8 18 [2] da 3a [2] dc 0f [2] f2 0f [2] cd 13 }

  condition:
    any of them
}