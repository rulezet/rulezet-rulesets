rule TTP_XOR_WriteProcessMemory_8027 {
  strings:
    $key_8027 = { d7 55 [2] e5 77 [2] e3 42 [2] cd 42 [2] f2 5e }

  condition:
    any of them
}