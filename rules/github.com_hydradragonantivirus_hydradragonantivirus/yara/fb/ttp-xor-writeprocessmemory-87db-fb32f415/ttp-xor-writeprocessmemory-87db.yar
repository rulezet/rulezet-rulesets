rule TTP_XOR_WriteProcessMemory_87db {
  strings:
    $key_87db = { d0 a9 [2] e2 8b [2] e4 be [2] ca be [2] f5 a2 }

  condition:
    any of them
}