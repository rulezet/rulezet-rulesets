rule TTP_XOR_WriteProcessMemory_b97a {
  strings:
    $key_b97a = { ee 08 [2] dc 2a [2] da 1f [2] f4 1f [2] cb 03 }

  condition:
    any of them
}