rule TTP_XOR_WriteProcessMemory_41db {
  strings:
    $key_41db = { 16 a9 [2] 24 8b [2] 22 be [2] 0c be [2] 33 a2 }

  condition:
    any of them
}