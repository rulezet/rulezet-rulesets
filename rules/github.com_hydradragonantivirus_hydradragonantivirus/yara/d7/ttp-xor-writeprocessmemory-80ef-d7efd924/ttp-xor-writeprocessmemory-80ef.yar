rule TTP_XOR_WriteProcessMemory_80ef {
  strings:
    $key_80ef = { d7 9d [2] e5 bf [2] e3 8a [2] cd 8a [2] f2 96 }

  condition:
    any of them
}