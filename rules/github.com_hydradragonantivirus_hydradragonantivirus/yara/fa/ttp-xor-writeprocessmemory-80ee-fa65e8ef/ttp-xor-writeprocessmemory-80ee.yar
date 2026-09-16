rule TTP_XOR_WriteProcessMemory_80ee {
  strings:
    $key_80ee = { d7 9c [2] e5 be [2] e3 8b [2] cd 8b [2] f2 97 }

  condition:
    any of them
}