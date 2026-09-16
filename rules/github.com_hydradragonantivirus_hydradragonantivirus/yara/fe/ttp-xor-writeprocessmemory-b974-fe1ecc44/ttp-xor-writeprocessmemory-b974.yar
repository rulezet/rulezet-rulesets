rule TTP_XOR_WriteProcessMemory_b974 {
  strings:
    $key_b974 = { ee 06 [2] dc 24 [2] da 11 [2] f4 11 [2] cb 0d }

  condition:
    any of them
}