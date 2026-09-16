rule TTP_XOR_WriteProcessMemory_b98d {
  strings:
    $key_b98d = { ee ff [2] dc dd [2] da e8 [2] f4 e8 [2] cb f4 }

  condition:
    any of them
}