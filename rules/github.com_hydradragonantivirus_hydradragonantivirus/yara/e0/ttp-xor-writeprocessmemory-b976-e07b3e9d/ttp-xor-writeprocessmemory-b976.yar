rule TTP_XOR_WriteProcessMemory_b976 {
  strings:
    $key_b976 = { ee 04 [2] dc 26 [2] da 13 [2] f4 13 [2] cb 0f }

  condition:
    any of them
}