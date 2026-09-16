rule TTP_XOR_WriteProcessMemory_b959 {
  strings:
    $key_b959 = { ee 2b [2] dc 09 [2] da 3c [2] f4 3c [2] cb 20 }

  condition:
    any of them
}