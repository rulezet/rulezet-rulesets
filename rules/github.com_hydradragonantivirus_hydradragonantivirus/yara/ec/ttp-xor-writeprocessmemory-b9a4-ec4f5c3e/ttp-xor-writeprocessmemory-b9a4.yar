rule TTP_XOR_WriteProcessMemory_b9a4 {
  strings:
    $key_b9a4 = { ee d6 [2] dc f4 [2] da c1 [2] f4 c1 [2] cb dd }

  condition:
    any of them
}