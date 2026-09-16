rule TTP_XOR_WriteProcessMemory_b9d8 {
  strings:
    $key_b9d8 = { ee aa [2] dc 88 [2] da bd [2] f4 bd [2] cb a1 }

  condition:
    any of them
}