rule TTP_XOR_WriteProcessMemory_75dd {
  strings:
    $key_75dd = { 22 af [2] 10 8d [2] 16 b8 [2] 38 b8 [2] 07 a4 }

  condition:
    any of them
}