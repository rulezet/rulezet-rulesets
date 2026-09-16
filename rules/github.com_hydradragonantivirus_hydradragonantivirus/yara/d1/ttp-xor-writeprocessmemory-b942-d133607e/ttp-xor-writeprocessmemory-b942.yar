rule TTP_XOR_WriteProcessMemory_b942 {
  strings:
    $key_b942 = { ee 30 [2] dc 12 [2] da 27 [2] f4 27 [2] cb 3b }

  condition:
    any of them
}