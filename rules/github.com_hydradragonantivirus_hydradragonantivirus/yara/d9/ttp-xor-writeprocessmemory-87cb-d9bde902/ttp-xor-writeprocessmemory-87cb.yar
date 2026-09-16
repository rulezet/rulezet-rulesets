rule TTP_XOR_WriteProcessMemory_87cb {
  strings:
    $key_87cb = { d0 b9 [2] e2 9b [2] e4 ae [2] ca ae [2] f5 b2 }

  condition:
    any of them
}