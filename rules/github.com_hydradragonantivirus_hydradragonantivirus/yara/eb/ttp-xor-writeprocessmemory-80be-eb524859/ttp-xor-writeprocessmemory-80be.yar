rule TTP_XOR_WriteProcessMemory_80be {
  strings:
    $key_80be = { d7 cc [2] e5 ee [2] e3 db [2] cd db [2] f2 c7 }

  condition:
    any of them
}