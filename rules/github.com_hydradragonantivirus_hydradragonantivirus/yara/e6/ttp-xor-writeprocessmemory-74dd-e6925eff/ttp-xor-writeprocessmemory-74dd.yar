rule TTP_XOR_WriteProcessMemory_74dd {
  strings:
    $key_74dd = { 23 af [2] 11 8d [2] 17 b8 [2] 39 b8 [2] 06 a4 }

  condition:
    any of them
}