rule TTP_XOR_WriteProcessMemory_96da {
  strings:
    $key_96da = { c1 a8 [2] f3 8a [2] f5 bf [2] db bf [2] e4 a3 }

  condition:
    any of them
}