rule TTP_XOR_WriteProcessMemory_7dab {
  strings:
    $key_7dab = { 2a d9 [2] 18 fb [2] 1e ce [2] 30 ce [2] 0f d2 }

  condition:
    any of them
}