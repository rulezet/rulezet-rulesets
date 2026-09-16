rule TTP_XOR_WriteProcessMemory_803c {
  strings:
    $key_803c = { d7 4e [2] e5 6c [2] e3 59 [2] cd 59 [2] f2 45 }

  condition:
    any of them
}