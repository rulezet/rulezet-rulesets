rule TTP_XOR_WriteProcessMemory_83ab {
  strings:
    $key_83ab = { d4 d9 [2] e6 fb [2] e0 ce [2] ce ce [2] f1 d2 }

  condition:
    any of them
}