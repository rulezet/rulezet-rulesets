rule TTP_XOR_WriteProcessMemory_93db {
  strings:
    $key_93db = { c4 a9 [2] f6 8b [2] f0 be [2] de be [2] e1 a2 }

  condition:
    any of them
}