rule TTP_XOR_WriteProcessMemory_bf6f {
  strings:
    $key_bf6f = { e8 1d [2] da 3f [2] dc 0a [2] f2 0a [2] cd 16 }

  condition:
    any of them
}