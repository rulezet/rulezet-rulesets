rule TTP_XOR_WriteProcessMemory_b9e0 {
  strings:
    $key_b9e0 = { ee 92 [2] dc b0 [2] da 85 [2] f4 85 [2] cb 99 }

  condition:
    any of them
}