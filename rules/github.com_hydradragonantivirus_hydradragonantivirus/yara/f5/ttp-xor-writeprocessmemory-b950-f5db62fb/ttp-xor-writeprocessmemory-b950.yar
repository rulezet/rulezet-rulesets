rule TTP_XOR_WriteProcessMemory_b950 {
  strings:
    $key_b950 = { ee 22 [2] dc 00 [2] da 35 [2] f4 35 [2] cb 29 }

  condition:
    any of them
}