rule TTP_XOR_WriteProcessMemory_94ab {
  strings:
    $key_94ab = { c3 d9 [2] f1 fb [2] f7 ce [2] d9 ce [2] e6 d2 }

  condition:
    any of them
}