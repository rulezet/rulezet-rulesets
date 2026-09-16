rule TTP_XOR_WriteProcessMemory_b914 {
  strings:
    $key_b914 = { ee 66 [2] dc 44 [2] da 71 [2] f4 71 [2] cb 6d }

  condition:
    any of them
}