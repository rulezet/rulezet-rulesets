rule TTP_XOR_WriteProcessMemory_40dd {
  strings:
    $key_40dd = { 17 af [2] 25 8d [2] 23 b8 [2] 0d b8 [2] 32 a4 }

  condition:
    any of them
}