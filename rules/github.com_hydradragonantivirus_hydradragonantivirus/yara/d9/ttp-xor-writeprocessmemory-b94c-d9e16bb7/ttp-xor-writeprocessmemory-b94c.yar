rule TTP_XOR_WriteProcessMemory_b94c {
  strings:
    $key_b94c = { ee 3e [2] dc 1c [2] da 29 [2] f4 29 [2] cb 35 }

  condition:
    any of them
}