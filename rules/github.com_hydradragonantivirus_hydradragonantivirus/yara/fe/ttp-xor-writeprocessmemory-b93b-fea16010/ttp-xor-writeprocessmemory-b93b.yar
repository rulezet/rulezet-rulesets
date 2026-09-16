rule TTP_XOR_WriteProcessMemory_b93b {
  strings:
    $key_b93b = { ee 49 [2] dc 6b [2] da 5e [2] f4 5e [2] cb 42 }

  condition:
    any of them
}