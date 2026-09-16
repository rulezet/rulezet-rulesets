rule TTP_XOR_WriteProcessMemory_b952 {
  strings:
    $key_b952 = { ee 20 [2] dc 02 [2] da 37 [2] f4 37 [2] cb 2b }

  condition:
    any of them
}