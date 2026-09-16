rule TTP_XOR_WriteProcessMemory_807e {
  strings:
    $key_807e = { d7 0c [2] e5 2e [2] e3 1b [2] cd 1b [2] f2 07 }

  condition:
    any of them
}