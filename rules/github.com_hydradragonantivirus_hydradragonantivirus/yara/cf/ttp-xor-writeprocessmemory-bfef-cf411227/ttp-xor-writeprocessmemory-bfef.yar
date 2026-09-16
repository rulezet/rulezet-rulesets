rule TTP_XOR_WriteProcessMemory_bfef {
  strings:
    $key_bfef = { e8 9d [2] da bf [2] dc 8a [2] f2 8a [2] cd 96 }

  condition:
    any of them
}