rule TTP_XOR_WriteProcessMemory_b94f {
  strings:
    $key_b94f = { ee 3d [2] dc 1f [2] da 2a [2] f4 2a [2] cb 36 }

  condition:
    any of them
}