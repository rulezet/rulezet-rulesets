rule TTP_XOR_WriteProcessMemory_b9e7 {
  strings:
    $key_b9e7 = { ee 95 [2] dc b7 [2] da 82 [2] f4 82 [2] cb 9e }

  condition:
    any of them
}