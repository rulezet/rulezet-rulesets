rule TTP_XOR_WriteProcessMemory_8048 {
  strings:
    $key_8048 = { d7 3a [2] e5 18 [2] e3 2d [2] cd 2d [2] f2 31 }

  condition:
    any of them
}