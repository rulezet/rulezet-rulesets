rule TTP_XOR_WriteProcessMemory_3fb4 {
  strings:
    $key_3fb4 = { 68 c6 [2] 5a e4 [2] 5c d1 [2] 72 d1 [2] 4d cd }

  condition:
    any of them
}