rule TTP_XOR_WriteProcessMemory_69bc {
  strings:
    $key_69bc = { 3e ce [2] 0c ec [2] 0a d9 [2] 24 d9 [2] 1b c5 }

  condition:
    any of them
}