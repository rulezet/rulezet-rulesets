rule TTP_XOR_WriteProcessMemory_2aab {
  strings:
    $key_2aab = { 7d d9 [2] 4f fb [2] 49 ce [2] 67 ce [2] 58 d2 }

  condition:
    any of them
}