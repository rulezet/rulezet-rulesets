rule TTP_XOR_WriteProcessMemory_7bab {
  strings:
    $key_7bab = { 2c d9 [2] 1e fb [2] 18 ce [2] 36 ce [2] 09 d2 }

  condition:
    any of them
}