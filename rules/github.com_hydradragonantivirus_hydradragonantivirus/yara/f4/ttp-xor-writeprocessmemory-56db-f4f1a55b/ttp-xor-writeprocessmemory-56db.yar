rule TTP_XOR_WriteProcessMemory_56db {
  strings:
    $key_56db = { 01 a9 [2] 33 8b [2] 35 be [2] 1b be [2] 24 a2 }

  condition:
    any of them
}