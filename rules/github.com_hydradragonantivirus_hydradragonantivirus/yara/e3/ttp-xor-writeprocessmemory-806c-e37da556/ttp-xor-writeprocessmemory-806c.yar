rule TTP_XOR_WriteProcessMemory_806c {
  strings:
    $key_806c = { d7 1e [2] e5 3c [2] e3 09 [2] cd 09 [2] f2 15 }

  condition:
    any of them
}