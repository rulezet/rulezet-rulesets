rule TTP_XOR_WriteProcessMemory_1bab {
  strings:
    $key_1bab = { 4c d9 [2] 7e fb [2] 78 ce [2] 56 ce [2] 69 d2 }

  condition:
    any of them
}