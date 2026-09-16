rule TTP_XOR_WriteProcessMemory_6eab {
  strings:
    $key_6eab = { 39 d9 [2] 0b fb [2] 0d ce [2] 23 ce [2] 1c d2 }

  condition:
    any of them
}