rule TTP_XOR_WriteProcessMemory_4edb {
  strings:
    $key_4edb = { 19 a9 [2] 2b 8b [2] 2d be [2] 03 be [2] 3c a2 }

  condition:
    any of them
}