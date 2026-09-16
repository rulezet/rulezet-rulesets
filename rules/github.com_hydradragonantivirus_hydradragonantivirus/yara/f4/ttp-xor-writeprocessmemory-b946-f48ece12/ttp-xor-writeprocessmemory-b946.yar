rule TTP_XOR_WriteProcessMemory_b946 {
  strings:
    $key_b946 = { ee 34 [2] dc 16 [2] da 23 [2] f4 23 [2] cb 3f }

  condition:
    any of them
}