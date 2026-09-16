rule TTP_XOR_WriteProcessMemory_968b {
  strings:
    $key_968b = { c1 f9 [2] f3 db [2] f5 ee [2] db ee [2] e4 f2 }

  condition:
    any of them
}