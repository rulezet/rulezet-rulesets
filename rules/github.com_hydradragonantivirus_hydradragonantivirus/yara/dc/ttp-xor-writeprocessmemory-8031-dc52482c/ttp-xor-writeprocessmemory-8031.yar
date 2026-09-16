rule TTP_XOR_WriteProcessMemory_8031 {
  strings:
    $key_8031 = { d7 43 [2] e5 61 [2] e3 54 [2] cd 54 [2] f2 48 }

  condition:
    any of them
}