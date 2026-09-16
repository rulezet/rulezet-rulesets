rule TTP_XOR_WriteProcessMemory_3ebc {
  strings:
    $key_3ebc = { 69 ce [2] 5b ec [2] 5d d9 [2] 73 d9 [2] 4c c5 }

  condition:
    any of them
}