rule TTP_XOR_WriteProcessMemory_83db {
  strings:
    $key_83db = { d4 a9 [2] e6 8b [2] e0 be [2] ce be [2] f1 a2 }

  condition:
    any of them
}