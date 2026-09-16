rule TTP_XOR_WriteProcessMemory_25dd {
  strings:
    $key_25dd = { 72 af [2] 40 8d [2] 46 b8 [2] 68 b8 [2] 57 a4 }

  condition:
    any of them
}