rule TTP_XOR_WriteProcessMemory_77bc {
  strings:
    $key_77bc = { 20 ce [2] 12 ec [2] 14 d9 [2] 3a d9 [2] 05 c5 }

  condition:
    any of them
}