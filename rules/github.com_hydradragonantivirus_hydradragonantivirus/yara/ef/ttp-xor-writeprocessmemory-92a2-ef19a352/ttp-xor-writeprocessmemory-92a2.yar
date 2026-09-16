rule TTP_XOR_WriteProcessMemory_92a2 {
  strings:
    $key_92a2 = { c5 d0 [2] f7 f2 [2] f1 c7 [2] df c7 [2] e0 db }

  condition:
    any of them
}