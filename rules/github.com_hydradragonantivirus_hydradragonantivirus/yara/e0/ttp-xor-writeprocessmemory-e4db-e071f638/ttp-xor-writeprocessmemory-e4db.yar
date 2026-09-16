rule TTP_XOR_WriteProcessMemory_e4db {
  strings:
    $key_e4db = { b3 a9 [2] 81 8b [2] 87 be [2] a9 be [2] 96 a2 }

  condition:
    any of them
}