rule TTP_XOR_WriteProcessMemory_b90a {
  strings:
    $key_b90a = { ee 78 [2] dc 5a [2] da 6f [2] f4 6f [2] cb 73 }

  condition:
    any of them
}