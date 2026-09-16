rule TTP_XOR_WriteProcessMemory_84bc {
  strings:
    $key_84bc = { d3 ce [2] e1 ec [2] e7 d9 [2] c9 d9 [2] f6 c5 }

  condition:
    any of them
}