rule TTP_XOR_WriteProcessMemory_b919 {
  strings:
    $key_b919 = { ee 6b [2] dc 49 [2] da 7c [2] f4 7c [2] cb 60 }

  condition:
    any of them
}