rule TTP_XOR_WriteProcessMemory_8078 {
  strings:
    $key_8078 = { d7 0a [2] e5 28 [2] e3 1d [2] cd 1d [2] f2 01 }

  condition:
    any of them
}