rule TTP_XOR_WriteProcessMemory_59ab {
  strings:
    $key_59ab = { 0e d9 [2] 3c fb [2] 3a ce [2] 14 ce [2] 2b d2 }

  condition:
    any of them
}