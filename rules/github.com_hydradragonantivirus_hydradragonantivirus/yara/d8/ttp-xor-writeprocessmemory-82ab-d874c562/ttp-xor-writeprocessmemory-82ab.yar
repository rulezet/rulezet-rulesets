rule TTP_XOR_WriteProcessMemory_82ab {
  strings:
    $key_82ab = { d5 d9 [2] e7 fb [2] e1 ce [2] cf ce [2] f0 d2 }

  condition:
    any of them
}