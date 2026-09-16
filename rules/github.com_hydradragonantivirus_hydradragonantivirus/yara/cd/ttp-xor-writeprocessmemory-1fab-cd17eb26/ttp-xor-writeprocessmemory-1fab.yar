rule TTP_XOR_WriteProcessMemory_1fab {
  strings:
    $key_1fab = { 48 d9 [2] 7a fb [2] 7c ce [2] 52 ce [2] 6d d2 }

  condition:
    any of them
}