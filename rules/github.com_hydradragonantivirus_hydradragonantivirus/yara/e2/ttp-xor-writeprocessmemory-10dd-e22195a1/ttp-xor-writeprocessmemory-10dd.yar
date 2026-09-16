rule TTP_XOR_WriteProcessMemory_10dd {
  strings:
    $key_10dd = { 47 af [2] 75 8d [2] 73 b8 [2] 5d b8 [2] 62 a4 }

  condition:
    any of them
}