rule TTP_XOR_WriteProcessMemory_b9b0 {
  strings:
    $key_b9b0 = { ee c2 [2] dc e0 [2] da d5 [2] f4 d5 [2] cb c9 }

  condition:
    any of them
}