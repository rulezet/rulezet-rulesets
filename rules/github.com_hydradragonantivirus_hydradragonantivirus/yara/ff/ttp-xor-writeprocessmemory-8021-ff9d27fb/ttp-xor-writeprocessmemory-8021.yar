rule TTP_XOR_WriteProcessMemory_8021 {
  strings:
    $key_8021 = { d7 53 [2] e5 71 [2] e3 44 [2] cd 44 [2] f2 58 }

  condition:
    any of them
}