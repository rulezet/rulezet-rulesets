rule TTP_XOR_WriteProcessMemory_0ba2 {
  strings:
    $key_0ba2 = { 5c d0 [2] 6e f2 [2] 68 c7 [2] 46 c7 [2] 79 db }

  condition:
    any of them
}