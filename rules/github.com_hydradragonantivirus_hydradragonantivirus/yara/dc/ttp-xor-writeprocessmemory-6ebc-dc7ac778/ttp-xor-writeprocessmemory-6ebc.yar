rule TTP_XOR_WriteProcessMemory_6ebc {
  strings:
    $key_6ebc = { 39 ce [2] 0b ec [2] 0d d9 [2] 23 d9 [2] 1c c5 }

  condition:
    any of them
}