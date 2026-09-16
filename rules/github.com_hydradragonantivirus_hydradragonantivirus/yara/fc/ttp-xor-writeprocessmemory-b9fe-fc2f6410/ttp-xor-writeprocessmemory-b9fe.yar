rule TTP_XOR_WriteProcessMemory_b9fe {
  strings:
    $key_b9fe = { ee 8c [2] dc ae [2] da 9b [2] f4 9b [2] cb 87 }

  condition:
    any of them
}