rule TTP_XOR_WriteProcessMemory_54dd {
  strings:
    $key_54dd = { 03 af [2] 31 8d [2] 37 b8 [2] 19 b8 [2] 26 a4 }

  condition:
    any of them
}