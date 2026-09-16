rule TTP_XOR_WriteProcessMemory_b924 {
  strings:
    $key_b924 = { ee 56 [2] dc 74 [2] da 41 [2] f4 41 [2] cb 5d }

  condition:
    any of them
}