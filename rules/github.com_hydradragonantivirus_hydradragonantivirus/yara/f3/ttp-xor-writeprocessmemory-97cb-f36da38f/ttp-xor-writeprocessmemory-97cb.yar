rule TTP_XOR_WriteProcessMemory_97cb {
  strings:
    $key_97cb = { c0 b9 [2] f2 9b [2] f4 ae [2] da ae [2] e5 b2 }

  condition:
    any of them
}