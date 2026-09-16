rule TTP_XOR_WriteProcessMemory_06db {
  strings:
    $key_06db = { 51 a9 [2] 63 8b [2] 65 be [2] 4b be [2] 74 a2 }

  condition:
    any of them
}