rule TTP_XOR_WriteProcessMemory_00db {
  strings:
    $key_00db = { 57 a9 [2] 65 8b [2] 63 be [2] 4d be [2] 72 a2 }

  condition:
    any of them
}