rule TTP_XOR_WriteProcessMemory_b96f {
  strings:
    $key_b96f = { ee 1d [2] dc 3f [2] da 0a [2] f4 0a [2] cb 16 }

  condition:
    any of them
}