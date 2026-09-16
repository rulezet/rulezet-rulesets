rule TTP_XOR_WriteProcessMemory_b8db {
  strings:
    $key_b8db = { ef a9 [2] dd 8b [2] db be [2] f5 be [2] ca a2 }

  condition:
    any of them
}