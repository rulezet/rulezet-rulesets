rule TTP_XOR_WriteProcessMemory_5bdb {
  strings:
    $key_5bdb = { 0c a9 [2] 3e 8b [2] 38 be [2] 16 be [2] 29 a2 }

  condition:
    any of them
}