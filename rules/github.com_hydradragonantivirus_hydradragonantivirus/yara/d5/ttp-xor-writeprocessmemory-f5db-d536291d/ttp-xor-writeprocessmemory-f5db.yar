rule TTP_XOR_WriteProcessMemory_f5db {
  strings:
    $key_f5db = { a2 a9 [2] 90 8b [2] 96 be [2] b8 be [2] 87 a2 }

  condition:
    any of them
}