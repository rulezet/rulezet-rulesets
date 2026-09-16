rule TTP_XOR_WriteProcessMemory_b9f1 {
  strings:
    $key_b9f1 = { ee 83 [2] dc a1 [2] da 94 [2] f4 94 [2] cb 88 }

  condition:
    any of them
}