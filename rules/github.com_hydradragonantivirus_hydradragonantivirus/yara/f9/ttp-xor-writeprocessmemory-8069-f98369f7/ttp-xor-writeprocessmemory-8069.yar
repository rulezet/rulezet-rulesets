rule TTP_XOR_WriteProcessMemory_8069 {
  strings:
    $key_8069 = { d7 1b [2] e5 39 [2] e3 0c [2] cd 0c [2] f2 10 }

  condition:
    any of them
}