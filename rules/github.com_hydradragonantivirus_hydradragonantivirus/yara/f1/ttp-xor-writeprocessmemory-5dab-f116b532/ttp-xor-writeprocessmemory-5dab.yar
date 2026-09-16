rule TTP_XOR_WriteProcessMemory_5dab {
  strings:
    $key_5dab = { 0a d9 [2] 38 fb [2] 3e ce [2] 10 ce [2] 2f d2 }

  condition:
    any of them
}