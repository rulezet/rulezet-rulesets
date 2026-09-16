rule TTP_XOR_WriteProcessMemory_b970 {
  strings:
    $key_b970 = { ee 02 [2] dc 20 [2] da 15 [2] f4 15 [2] cb 09 }

  condition:
    any of them
}