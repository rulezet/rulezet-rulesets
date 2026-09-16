rule TTP_XOR_WriteProcessMemory_5fab {
  strings:
    $key_5fab = { 08 d9 [2] 3a fb [2] 3c ce [2] 12 ce [2] 2d d2 }

  condition:
    any of them
}