rule TTP_XOR_WriteProcessMemory_0edb {
  strings:
    $key_0edb = { 59 a9 [2] 6b 8b [2] 6d be [2] 43 be [2] 7c a2 }

  condition:
    any of them
}