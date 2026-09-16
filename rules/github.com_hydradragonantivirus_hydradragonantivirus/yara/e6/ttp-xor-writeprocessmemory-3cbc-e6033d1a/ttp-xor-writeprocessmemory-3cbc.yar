rule TTP_XOR_WriteProcessMemory_3cbc {
  strings:
    $key_3cbc = { 6b ce [2] 59 ec [2] 5f d9 [2] 71 d9 [2] 4e c5 }

  condition:
    any of them
}