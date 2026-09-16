rule TTP_XOR_WriteProcessMemory_2ebc {
  strings:
    $key_2ebc = { 79 ce [2] 4b ec [2] 4d d9 [2] 63 d9 [2] 5c c5 }

  condition:
    any of them
}