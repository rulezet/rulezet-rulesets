rule TTP_XOR_WriteProcessMemory_45db {
  strings:
    $key_45db = { 12 a9 [2] 20 8b [2] 26 be [2] 08 be [2] 37 a2 }

  condition:
    any of them
}