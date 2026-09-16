rule TTP_XOR_WriteProcessMemory_4bbc {
  strings:
    $key_4bbc = { 1c ce [2] 2e ec [2] 28 d9 [2] 06 d9 [2] 39 c5 }

  condition:
    any of them
}