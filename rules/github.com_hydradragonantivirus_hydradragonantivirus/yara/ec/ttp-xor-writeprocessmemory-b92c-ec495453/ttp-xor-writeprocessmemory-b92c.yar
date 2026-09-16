rule TTP_XOR_WriteProcessMemory_b92c {
  strings:
    $key_b92c = { ee 5e [2] dc 7c [2] da 49 [2] f4 49 [2] cb 55 }

  condition:
    any of them
}