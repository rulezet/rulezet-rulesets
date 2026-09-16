rule TTP_XOR_WriteProcessMemory_30db {
  strings:
    $key_30db = { 67 a9 [2] 55 8b [2] 53 be [2] 7d be [2] 42 a2 }

  condition:
    any of them
}