rule TTP_XOR_WriteProcessMemory_b943 {
  strings:
    $key_b943 = { ee 31 [2] dc 13 [2] da 26 [2] f4 26 [2] cb 3a }

  condition:
    any of them
}