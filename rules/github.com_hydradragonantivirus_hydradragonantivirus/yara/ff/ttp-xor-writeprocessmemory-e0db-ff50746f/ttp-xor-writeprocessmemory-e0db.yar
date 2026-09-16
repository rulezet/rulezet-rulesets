rule TTP_XOR_WriteProcessMemory_e0db {
  strings:
    $key_e0db = { b7 a9 [2] 85 8b [2] 83 be [2] ad be [2] 92 a2 }

  condition:
    any of them
}