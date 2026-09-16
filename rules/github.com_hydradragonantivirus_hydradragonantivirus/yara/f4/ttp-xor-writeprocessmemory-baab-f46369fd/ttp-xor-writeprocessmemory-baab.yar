rule TTP_XOR_WriteProcessMemory_baab {
  strings:
    $key_baab = { ed d9 [2] df fb [2] d9 ce [2] f7 ce [2] c8 d2 }

  condition:
    any of them
}