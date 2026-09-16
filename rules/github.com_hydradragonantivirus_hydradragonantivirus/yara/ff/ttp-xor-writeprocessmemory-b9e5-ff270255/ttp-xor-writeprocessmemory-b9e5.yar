rule TTP_XOR_WriteProcessMemory_b9e5 {
  strings:
    $key_b9e5 = { ee 97 [2] dc b5 [2] da 80 [2] f4 80 [2] cb 9c }

  condition:
    any of them
}