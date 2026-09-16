rule TTP_XOR_WriteProcessMemory_8033 {
  strings:
    $key_8033 = { d7 41 [2] e5 63 [2] e3 56 [2] cd 56 [2] f2 4a }

  condition:
    any of them
}