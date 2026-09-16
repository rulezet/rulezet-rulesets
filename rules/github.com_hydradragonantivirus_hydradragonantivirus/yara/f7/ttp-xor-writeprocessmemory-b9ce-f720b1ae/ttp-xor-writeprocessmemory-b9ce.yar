rule TTP_XOR_WriteProcessMemory_b9ce {
  strings:
    $key_b9ce = { ee bc [2] dc 9e [2] da ab [2] f4 ab [2] cb b7 }

  condition:
    any of them
}