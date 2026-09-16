rule TTP_XOR_WriteProcessMemory_d0db {
  strings:
    $key_d0db = { 87 a9 [2] b5 8b [2] b3 be [2] 9d be [2] a2 a2 }

  condition:
    any of them
}