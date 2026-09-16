rule TTP_XOR_WriteProcessMemory_4bdb {
  strings:
    $key_4bdb = { 1c a9 [2] 2e 8b [2] 28 be [2] 06 be [2] 39 a2 }

  condition:
    any of them
}