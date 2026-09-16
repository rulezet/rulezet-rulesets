rule TTP_XOR_WriteProcessMemory_96bc {
  strings:
    $key_96bc = { c1 ce [2] f3 ec [2] f5 d9 [2] db d9 [2] e4 c5 }

  condition:
    any of them
}