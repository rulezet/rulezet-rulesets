rule TTP_XOR_WriteProcessMemory_39bc {
  strings:
    $key_39bc = { 6e ce [2] 5c ec [2] 5a d9 [2] 74 d9 [2] 4b c5 }

  condition:
    any of them
}