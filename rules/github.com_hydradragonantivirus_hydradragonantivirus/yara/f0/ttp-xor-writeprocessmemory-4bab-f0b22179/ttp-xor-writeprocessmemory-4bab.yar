rule TTP_XOR_WriteProcessMemory_4bab {
  strings:
    $key_4bab = { 1c d9 [2] 2e fb [2] 28 ce [2] 06 ce [2] 39 d2 }

  condition:
    any of them
}