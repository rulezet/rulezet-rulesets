rule TTP_XOR_WriteProcessMemory_b966 {
  strings:
    $key_b966 = { ee 14 [2] dc 36 [2] da 03 [2] f4 03 [2] cb 1f }

  condition:
    any of them
}