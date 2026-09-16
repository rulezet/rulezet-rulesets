rule TTP_XOR_WriteProcessMemory_805d {
  strings:
    $key_805d = { d7 2f [2] e5 0d [2] e3 38 [2] cd 38 [2] f2 24 }

  condition:
    any of them
}