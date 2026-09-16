rule TTP_XOR_WriteProcessMemory_6dab {
  strings:
    $key_6dab = { 3a d9 [2] 08 fb [2] 0e ce [2] 20 ce [2] 1f d2 }

  condition:
    any of them
}