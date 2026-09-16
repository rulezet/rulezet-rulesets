rule TTP_XOR_WriteProcessMemory_b2db {
  strings:
    $key_b2db = { e5 a9 [2] d7 8b [2] d1 be [2] ff be [2] c0 a2 }

  condition:
    any of them
}