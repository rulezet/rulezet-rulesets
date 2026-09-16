rule TTP_XOR_WriteProcessMemory_8025 {
  strings:
    $key_8025 = { d7 57 [2] e5 75 [2] e3 40 [2] cd 40 [2] f2 5c }

  condition:
    any of them
}