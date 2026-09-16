rule TTP_XOR_WriteProcessMemory_3eab {
  strings:
    $key_3eab = { 69 d9 [2] 5b fb [2] 5d ce [2] 73 ce [2] 4c d2 }

  condition:
    any of them
}