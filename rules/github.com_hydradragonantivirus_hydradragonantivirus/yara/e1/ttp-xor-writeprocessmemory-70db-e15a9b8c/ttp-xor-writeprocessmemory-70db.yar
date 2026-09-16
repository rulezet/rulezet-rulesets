rule TTP_XOR_WriteProcessMemory_70db {
  strings:
    $key_70db = { 27 a9 [2] 15 8b [2] 13 be [2] 3d be [2] 02 a2 }

  condition:
    any of them
}