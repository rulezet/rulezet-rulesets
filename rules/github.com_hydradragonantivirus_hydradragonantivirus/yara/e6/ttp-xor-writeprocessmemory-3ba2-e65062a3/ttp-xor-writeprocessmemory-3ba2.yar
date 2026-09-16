rule TTP_XOR_WriteProcessMemory_3ba2 {
  strings:
    $key_3ba2 = { 6c d0 [2] 5e f2 [2] 58 c7 [2] 76 c7 [2] 49 db }

  condition:
    any of them
}