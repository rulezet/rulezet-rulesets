rule TTP_XOR_WriteProcessMemory_ecbc {
  strings:
    $key_ecbc = { bb ce [2] 89 ec [2] 8f d9 [2] a1 d9 [2] 9e c5 }

  condition:
    any of them
}