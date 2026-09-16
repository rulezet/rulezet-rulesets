rule TTP_XOR_WriteProcessMemory_b9cf {
  strings:
    $key_b9cf = { ee bd [2] dc 9f [2] da aa [2] f4 aa [2] cb b6 }

  condition:
    any of them
}