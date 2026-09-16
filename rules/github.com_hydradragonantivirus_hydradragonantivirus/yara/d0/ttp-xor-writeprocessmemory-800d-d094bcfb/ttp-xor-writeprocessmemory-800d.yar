rule TTP_XOR_WriteProcessMemory_800d {
  strings:
    $key_800d = { d7 7f [2] e5 5d [2] e3 68 [2] cd 68 [2] f2 74 }

  condition:
    any of them
}