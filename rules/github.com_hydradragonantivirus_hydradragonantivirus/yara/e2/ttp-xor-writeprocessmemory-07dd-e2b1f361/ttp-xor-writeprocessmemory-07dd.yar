rule TTP_XOR_WriteProcessMemory_07dd {
  strings:
    $key_07dd = { 50 af [2] 62 8d [2] 64 b8 [2] 4a b8 [2] 75 a4 }

  condition:
    any of them
}