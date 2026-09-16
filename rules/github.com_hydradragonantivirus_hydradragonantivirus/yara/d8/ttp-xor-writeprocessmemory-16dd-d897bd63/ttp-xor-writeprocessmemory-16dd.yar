rule TTP_XOR_WriteProcessMemory_16dd {
  strings:
    $key_16dd = { 41 af [2] 73 8d [2] 75 b8 [2] 5b b8 [2] 64 a4 }

  condition:
    any of them
}