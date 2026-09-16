rule TTP_XOR_WriteProcessMemory_b9f0 {
  strings:
    $key_b9f0 = { ee 82 [2] dc a0 [2] da 95 [2] f4 95 [2] cb 89 }

  condition:
    any of them
}