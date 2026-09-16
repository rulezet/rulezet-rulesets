rule TTP_XOR_WriteProcessMemory_55dd {
  strings:
    $key_55dd = { 02 af [2] 30 8d [2] 36 b8 [2] 18 b8 [2] 27 a4 }

  condition:
    any of them
}