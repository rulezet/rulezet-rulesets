rule TTP_XOR_WriteProcessMemory_b939 {
  strings:
    $key_b939 = { ee 4b [2] dc 69 [2] da 5c [2] f4 5c [2] cb 40 }

  condition:
    any of them
}