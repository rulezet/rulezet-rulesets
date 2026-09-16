rule TTP_XOR_WriteProcessMemory_a2db {
  strings:
    $key_a2db = { f5 a9 [2] c7 8b [2] c1 be [2] ef be [2] d0 a2 }

  condition:
    any of them
}