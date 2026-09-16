rule TTP_XOR_WriteProcessMemory_b99c {
  strings:
    $key_b99c = { ee ee [2] dc cc [2] da f9 [2] f4 f9 [2] cb e5 }

  condition:
    any of them
}