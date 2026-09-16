rule TTP_XOR_WriteProcessMemory_b9d2 {
  strings:
    $key_b9d2 = { ee a0 [2] dc 82 [2] da b7 [2] f4 b7 [2] cb ab }

  condition:
    any of them
}