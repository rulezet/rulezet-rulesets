rule TTP_XOR_WriteProcessMemory_beab {
  strings:
    $key_beab = { e9 d9 [2] db fb [2] dd ce [2] f3 ce [2] cc d2 }

  condition:
    any of them
}