rule TTP_XOR_WriteProcessMemory_5fbc {
  strings:
    $key_5fbc = { 08 ce [2] 3a ec [2] 3c d9 [2] 12 d9 [2] 2d c5 }

  condition:
    any of them
}