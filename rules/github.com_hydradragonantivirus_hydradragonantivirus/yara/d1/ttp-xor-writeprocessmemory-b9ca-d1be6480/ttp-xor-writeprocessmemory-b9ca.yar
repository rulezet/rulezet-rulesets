rule TTP_XOR_WriteProcessMemory_b9ca {
  strings:
    $key_b9ca = { ee b8 [2] dc 9a [2] da af [2] f4 af [2] cb b3 }

  condition:
    any of them
}