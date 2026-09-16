rule TTP_XOR_WriteProcessMemory_b99a {
  strings:
    $key_b99a = { ee e8 [2] dc ca [2] da ff [2] f4 ff [2] cb e3 }

  condition:
    any of them
}