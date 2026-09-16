rule TTP_XOR_WriteProcessMemory_b9c4 {
  strings:
    $key_b9c4 = { ee b6 [2] dc 94 [2] da a1 [2] f4 a1 [2] cb bd }

  condition:
    any of them
}