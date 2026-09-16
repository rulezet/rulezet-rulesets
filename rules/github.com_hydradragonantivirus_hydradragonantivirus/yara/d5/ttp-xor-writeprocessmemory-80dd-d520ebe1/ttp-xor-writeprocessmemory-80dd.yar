rule TTP_XOR_WriteProcessMemory_80dd {
  strings:
    $key_80dd = { d7 af [2] e5 8d [2] e3 b8 [2] cd b8 [2] f2 a4 }

  condition:
    any of them
}