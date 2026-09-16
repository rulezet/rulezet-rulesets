rule TTP_XOR_WriteProcessMemory_b9b7 {
  strings:
    $key_b9b7 = { ee c5 [2] dc e7 [2] da d2 [2] f4 d2 [2] cb ce }

  condition:
    any of them
}