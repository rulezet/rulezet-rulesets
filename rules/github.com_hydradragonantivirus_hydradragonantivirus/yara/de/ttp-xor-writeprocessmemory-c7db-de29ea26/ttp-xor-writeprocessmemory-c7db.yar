rule TTP_XOR_WriteProcessMemory_c7db {
  strings:
    $key_c7db = { 90 a9 [2] a2 8b [2] a4 be [2] 8a be [2] b5 a2 }

  condition:
    any of them
}