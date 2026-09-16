rule TTP_XOR_WriteProcessMemory_b975 {
  strings:
    $key_b975 = { ee 07 [2] dc 25 [2] da 10 [2] f4 10 [2] cb 0c }

  condition:
    any of them
}