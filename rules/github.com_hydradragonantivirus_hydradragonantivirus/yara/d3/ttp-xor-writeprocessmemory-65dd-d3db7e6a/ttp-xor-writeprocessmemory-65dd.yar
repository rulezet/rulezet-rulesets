rule TTP_XOR_WriteProcessMemory_65dd {
  strings:
    $key_65dd = { 32 af [2] 00 8d [2] 06 b8 [2] 28 b8 [2] 17 a4 }

  condition:
    any of them
}