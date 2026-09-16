rule TTP_XOR_WriteProcessMemory_8aab {
  strings:
    $key_8aab = { dd d9 [2] ef fb [2] e9 ce [2] c7 ce [2] f8 d2 }

  condition:
    any of them
}